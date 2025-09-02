#![doc = include_str!("../README.md")]
#![warn(
    clippy::as_conversions,
    clippy::undocumented_unsafe_blocks,
    missing_docs
)]
use dispatch2::{DispatchObject, DispatchQueue, DispatchRetained, DispatchSource};
use std::{
    collections::VecDeque,
    ffi::{CString, c_void},
    future::Future,
    marker::PhantomData,
    mem::{self, ManuallyDrop, MaybeUninit},
    sync::{Arc, Mutex, OnceLock},
    task::{Poll, Waker},
    time::Duration,
};

mod ffi;
pub use ffi::{KernError, audit_token_t};

/// 1MB
///
/// This value isn't based on anything specific, its just somewhere between `u32::MAX` and Apple's
/// private hint of 256KB being "reliable depending on system conditions". We aren't a criticial system
/// service though, so occasional edge cases are OK.
///
/// This could be expanded into the GB range if support for out-of-line data is implemented.
const DEFAULT_MAX_MSG_SEND_SIZE_BYTES: u32 = 1_000_000;

const LENGTH_PREFIX_SIZE: usize = size_of::<usize>();

/// Failure cases that come from interacting with either a [Client] or [Server].
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// An unrecoverable error that occured when interacting with a Mach port.
    ///
    /// These are unexpected during normal operation.
    OsError(ffi::KernError),
    /// A listener failed to bind to the requested service name or a sender wasn't able
    /// to find the requested service.
    RegistrationError {
        /// The underlying error code of the failure.
        code: ffi::kern_return_t,
        /// The human-readable description of the error code.
        description: String,
    },
    /// A listener received an incorrect or unknown type of message it couldn't handle.
    CorruptMessage,
    /// A message being processed by either a send operation or the receiver was too large
    /// to fit reliably.
    MessageTooLarge,
    /// A message failed to be sent by a [Client] in the requested amount of time.
    FailedToSend,
    /// A client failed to receive the expected response message from the server it requested.
    NoReply,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OsError(err) => {
                f.write_str("mach call failed unexpectedly: ")?;
                f.write_fmt(format_args!("'{}'", err))
            }
            Error::RegistrationError { code, description } => {
                f.write_fmt(format_args!("{description} ({code})"))
            }
            Error::CorruptMessage => f.write_str("received unknown or corrupt message"),
            Error::MessageTooLarge => f.write_str("message was too large to handle"),
            Error::FailedToSend => f.write_str("failed to send message in expected timeframe"),
            Error::NoReply => f.write_str(
                "failed to receive reply from server; the server ignored the request or timed out",
            ),
        }
    }
}

fn allocate_new_port(release_with: ffi::MachPortReleaser) -> Result<ffi::MachPort, Error> {
    let mut local_port = ffi::MACH_PORT_NULL;
    // SAFETY: The task is the current one, its valid to allocate a new port in your task, and
    // `reply_port` is valid to write a mach right into.
    unsafe {
        ffi::mach_port_allocate(
            ffi::mach_task_self(),
            ffi::MACH_PORT_RIGHT_RECEIVE,
            &mut local_port,
        )
        .map_err(Error::OsError)?;
    }

    Ok(ffi::MachPort {
        inner: local_port,
        release: release_with,
    })
}

/// A client that can connect to an existing mach service and
/// send it messages, optionally receiving data back in reply.
pub struct Client {
    server_port: ffi::MachPort,
    send_timeout: Option<Duration>,
    recv_timeout: Option<Duration>,
}

impl Client {
    /// Connects to the named mach service under the curret device's user session, if it already exists.
    ///
    /// By default, operations performed by this client will block until ready. These can be configured with
    /// the [Client::set_send_timeout] and (for replies) [Client::set_recv_timeout] methods.
    pub fn connect(service_name: &str) -> Result<Self, Error> {
        let service_name = CString::new(service_name).unwrap();

        let mut sender_port = ffi::MACH_PORT_NULL;
        // SAFETY: `service_name` is a valid NULL-terminated string and `sender_port` is valid
        // to write a mach port right into.
        unsafe {
            ffi::bootstrap_look_up(
                ffi::bootstrap_port,
                service_name.as_ptr().cast(),
                &mut sender_port,
            )
            .map_err(|e| Error::RegistrationError {
                code: e.0.code(),
                description: e.description(),
            })?;
        }

        Ok(Self {
            server_port: ffi::MachPort {
                inner: sender_port,
                release: ffi::mach_port_deallocate,
            },
            send_timeout: None,
            recv_timeout: None,
        })
    }

    /// Sets the maximum duration to wait for a mach service's current server to accept the message.
    ///
    /// Setting `new_timeout` to [None] restores the default indefinite blocking behavior.
    pub fn set_send_timeout(&mut self, new_timeout: Option<Duration>) {
        self.send_timeout = new_timeout;
    }

    /// Sets the maximum duration to wait for a mach service to process a sent message
    /// and return the reply.
    ///
    /// Setting `new_timeout` to [None] restores the default indefinite blocking behavior.
    pub fn set_recv_timeout(&mut self, new_timeout: Option<Duration>) {
        self.recv_timeout = new_timeout;
    }

    /// Sends a message to the connected service, blocking until there's room in the receiver's queue
    /// to accept the message.
    ///
    /// If the server is actively listening, this _should_ be instant.
    pub fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        send_mach_message(
            &self.server_port,
            data,
            ReplyMode::Client {
                client_mode: ReplyInterest::SenderUninterested,
                timeout: self.send_timeout,
            },
        )
    }

    /// Send a message to the connected service, blocking until there's room in the receiver's queue
    /// to accept the message.
    ///
    /// Once the message has been delivered, this then blocks until the mach service has responded.
    pub fn send_with_reply(&mut self, data: &[u8]) -> Result<NewMessage<Client>, Error> {
        // Allocate and setup the mach port to give to the server to send us data back on.
        let reply_port = allocate_new_port(ffi::mach_port_deallocate)?;

        send_mach_message(
            &self.server_port,
            data,
            ReplyMode::Client {
                client_mode: ReplyInterest::SenderInterested(&reply_port),
                timeout: self.send_timeout,
            },
        )?;
        read_mach_message(
            &reply_port,
            DEFAULT_MAX_MSG_SEND_SIZE_BYTES,
            RecvMode::ClientReply,
        )
    }
}

// Only create one queue per version of the library in a process. This keeps
// the thread overhead low.
static SERVER_EVENT_QUEUE: OnceLock<DispatchRetained<DispatchQueue>> = OnceLock::new();

#[derive(Debug)]
enum DispatchState {
    Idle,
    Polling(Waker),
    Ready {
        message_batch: VecDeque<Result<NewMessage<Server>, Error>>,
    },
}

#[derive(Clone)]
struct MachSource(DispatchRetained<DispatchSource>);

impl MachSource {
    fn port(&self) -> ManuallyDrop<ffi::MachPort> {
        #[expect(clippy::as_conversions)]
        ManuallyDrop::new(ffi::MachPort {
            inner: self.0.handle() as ffi::mach_port_t,
            release: ffi::mach_port_destroy,
        })
    }

    fn owned_port(&mut self) -> ffi::MachPort {
        #[expect(clippy::as_conversions)]
        ffi::MachPort {
            inner: self.0.handle() as ffi::mach_port_t,
            release: ffi::mach_port_destroy,
        }
    }
}

struct ServerDispatchContext {
    poll_state: DispatchState,
    // This will only be released once the dispatch source cancel handler
    // has been called.
    source_port: MachSource,
    max_msg_size_bytes: u32,
}

type ServerSharedContext = Arc<Mutex<ServerDispatchContext>>;

/// A mach service that can register and bind to a specific service name, asynchronously
/// listening for incoming messages from clients on the same device.
///
/// There can only be one [Server] for any given service name in a user login session at a time.
pub struct Server {
    context: ServerSharedContext,
    dispatch_source: MachSource,
    max_msg_size_bytes: u32,
    saw_fatal_error: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.dispatch_source.0.cancel();
    }
}

impl Server {
    /// 2GB
    ///
    /// It is unlikely this will ever be hit because mach messages in the real world
    /// can't get this big without out-of-line data, which we currently don't implement support for.
    /// Even then its quite large and configurability can come later if needed.
    const DEFAULT_MAX_MSG_SIZE_BYTES: u32 = 2_000_000_000;

    extern "C" fn msg_ready_dispatch_handler(context: *mut c_void) {
        // SAFETY: This can only be called from a dispatch source handler we configure and the type is kept in sync.
        //
        // We don't own the data though, so use `ManuallyDrop` to prevent freeing the context.
        let outer_context =
            unsafe { ManuallyDrop::new(ServerSharedContext::from_raw(context.cast())) };

        // If the lock has been poisioned let the future polling handle it, since thats a panic-supporting context.
        let Ok(mut context) = outer_context.lock() else {
            return;
        };

        let current_state = mem::replace(&mut context.poll_state, DispatchState::Idle);
        if let DispatchState::Polling(waker) = current_state {
            // If the listener is currently being polled/streamed, we need to pause delivery of notifications to this
            // callback to prevent the state getting out of sync with the future's polling.
            //
            // Otherwise we will keep getting called multiple times as long as a message is inside the port's queue with no
            // future to alert, such as when we get messages before the listener starts or if we get several messages delivered
            // very fast.
            context.source_port.0.suspend();

            let port = context.source_port.port();

            // Drain the mach port's underlying queue so that we balance out the Future's polling state
            // with the source's read-ready signal.
            let mut message_batch = VecDeque::new();
            loop {
                match read_mach_message(&port, context.max_msg_size_bytes, RecvMode::Server) {
                    Err(Error::OsError(e)) if e.code() == ffi::MACH_RCV_TIMED_OUT => {
                        break;
                    }
                    msg => message_batch.push_back(msg),
                }
            }

            if !message_batch.is_empty() {
                context.poll_state = DispatchState::Ready { message_batch };
                waker.wake();
            } else {
                // With any batched messages clear, we can start handling receive-ready events again.
                context.source_port.0.resume();
            }
        } else {
            // If we aren't being polled, there's nothing to do. This should be unreachable
            // but its better to not panic when possible.
            context.poll_state = current_state;
        }
    }

    extern "C" fn source_cancel_receiver(context: *mut c_void) {
        // SAFETY: The context pointer is always the same one we originally provided our source
        // and the type is kept in sync.
        let ctx = unsafe { ServerSharedContext::from_raw(context.cast()) };
        if let Ok(mut context) = ctx.lock() {
            // Release the mach port now that we know libdispatch is safely done with it
            // and has detached all references.
            drop(context.source_port.owned_port());
        }
    }

    /// Registers `service_name` exclusively to the current process through the OS.
    ///
    /// This returns an error if another service has already registered `service_name`.
    pub fn register(service_name: &str) -> Result<Self, Error> {
        let service_name = CString::new(service_name).unwrap();

        // Allocate a new task (process) local mach port that we are the exclusive owners of.
        //
        // For the server-owned listener port we destroy it on drop so that the `service_name` can instantly be re-bound
        // if needed without a system restart. Otherwise the service name may be temporarily unusable later. Its unclear if
        // this behavior is an artifact of much older (and unsupported) macOS versions or not but its what Chromium's `breakpad`
        // handler does so it can't hurt to be cautious, pending further testing.
        let mut service_port = allocate_new_port(ffi::mach_port_destroy)?;

        // Use our ownership to add a send right to the port too. We need to do this so we can give it to launchd, who then
        // clones it to other senders on demand.
        //
        // SAFETY: The `service_port` is a valid mach port with a receive right, which means we can get send rights from it
        // and all the parameters are correct.
        unsafe {
            ffi::mach_port_insert_right(
                ffi::mach_task_self(),
                service_port.inner,
                service_port.inner,
                ffi::MACH_MSG_TYPE_MAKE_SEND,
            )
            .map_err(Error::OsError)?;
        };

        // Register the server's listening port with the bootstrap server (launchd).
        //
        // launchd then creates a temporary mach service registration bound to this process.
        //
        // SAFETY: `service_name` is a valid NULL-terminated string and `service_port` is a valid mach
        // port with a send right we can give to launchd.
        unsafe {
            ffi::bootstrap_check_in(
                ffi::bootstrap_port,
                service_name.as_ptr().cast(),
                &mut service_port.inner,
            )
            .map_err(|e| Error::RegistrationError {
                code: e.0.code(),
                description: e.description(),
            })?;
        }

        // We construct a crate-bound dispatch queue for receiving readable/ready event signals.
        // See https://mjtsai.com/blog/2021/03/16/underused-and-overused-gcd-patterns/ for rationale of the parameters.
        let event_queue = SERVER_EVENT_QUEUE.get_or_init(|| {
            let attrs = dispatch2::DispatchQueueAttr::with_autorelease_frequency(
                None,
                dispatch2::DispatchAutoReleaseFrequency::WORK_ITEM,
            );
            let target = DispatchQueue::global_queue(
                dispatch2::GlobalQueueIdentifier::QualityOfService(dispatch2::DispatchQoS::Default),
            );
            DispatchQueue::new_with_target(
                "org.complexspaces.mach-listener.server-event-handler",
                Some(&attrs),
                Some(&target),
            )
        });

        // https://developer.apple.com/documentation/dispatch/dispatch_source_type_mach_recv
        //
        // SAFETY: The even type is a valid system-defined static and the service port is valid to
        // receive on.
        let source = unsafe {
            // We don't want to release the port early, it will be released when the source
            // is canceled.
            let service_port = ManuallyDrop::new(service_port);
            // We are required to cast the mach port handle into a generic dispatch source handle.
            #[expect(clippy::as_conversions)]
            DispatchSource::new(
                std::ptr::addr_of!(dispatch2::_dispatch_source_type_mach_recv).cast_mut(),
                service_port.inner as usize,
                0,
                Some(event_queue),
            )
        };

        // XXX: Per https://developer.apple.com/documentation/dispatch/dispatch_source_set_cancel_handler_f, this MUST
        // be set when using a mach port as the source, as its the only way to deallocate the port safely.
        source.set_cancel_handler_f(Self::source_cancel_receiver);
        source.set_event_handler_f(Self::msg_ready_dispatch_handler);

        let source = MachSource(source);

        let context = Arc::new(Mutex::new(ServerDispatchContext {
            poll_state: DispatchState::Idle,
            source_port: source.clone(),
            max_msg_size_bytes: Self::DEFAULT_MAX_MSG_SIZE_BYTES,
        }));

        // SAFETY: The context pointer is a clone of a thread-safe data structure and won't be freed prematurely.
        // We always set this before the state can activate, so the closure will never receive a `NULL` context.
        unsafe {
            source
                .0
                .set_context(Arc::into_raw(Arc::clone(&context)).cast_mut().cast())
        };

        source.0.activate();

        Ok(Self {
            context,
            dispatch_source: source,
            max_msg_size_bytes: Self::DEFAULT_MAX_MSG_SIZE_BYTES,
            saw_fatal_error: false,
        })
    }

    /// Returns an async stream that can be awaited to receive messages that arrive from clients
    /// connected to this [Server]'s service name. Messages are returned from the stream in the order they arrive.
    ///
    /// Any existing messages that were received before `listen` is `await`ed will be returned first before any new messages.
    ///
    /// You may need to pin this stream's future before `.await`. [std::pin::pin!] or [Box::pin] can be used for this purpose.
    pub fn listen(
        &mut self,
    ) -> impl futures_util::Stream<Item = Result<NewMessage<Server>, Error>> + '_ {
        struct StreamState<'a> {
            context: &'a Mutex<ServerDispatchContext>,
            source: &'a MachSource,
            max_msg_size_bytes: u32,
            saw_fatal_error: &'a mut bool,
        }

        let state = StreamState {
            context: &self.context,
            source: &self.dispatch_source,
            max_msg_size_bytes: self.max_msg_size_bytes,
            saw_fatal_error: &mut self.saw_fatal_error,
        };

        futures_util::stream::unfold(state, |state| async {
            // Only check this on each stream poll, so that fatal errors can be seen by the caller
            // instead of dropped inside this stream.
            if *state.saw_fatal_error {
                return None;
            }

            let next_msg = ServerRecv {
                context: state.context,
                source: state.source,
                max_msg_size_bytes: state.max_msg_size_bytes,
            };
            let message = next_msg.await;

            // If we had an unknown error from the OS during receiving, something has
            // broken and its unlikely any future messages will work either.
            if let Err(Error::OsError(_)) = message.as_ref() {
                *state.saw_fatal_error = true;
            }

            Some((message, state))
        })
    }
}

/// A new message that was received either by the server or in response to a message
/// originally sent by the client.
///
/// If a client wanted a response from the server, [NewMessage::reply] is used to return it.
pub struct NewMessage<Side> {
    /// The original bytes sent by the other end of the connection.
    pub data: Vec<u8>,
    /// An arbitrary ID associated with the message. If one wasn't set this is `0`.
    pub msg_id: i32,
    /// The absolute identity of the process who sent this message in the form of an [audit token].
    ///
    /// This can be used to collect information or securely verify the sender of a messsage if needed.
    ///
    /// [audit token]: https://knight.sc/reverse%20engineering/2020/03/20/audit-tokens-explained.html
    pub sender_identity: ffi::audit_token_t,
    reply_port: Option<ffi::MachPort>,
    _side: PhantomData<Side>,
}

impl<Side> std::fmt::Debug for NewMessage<Side> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewMessage")
            .field("data", &self.data)
            .field("msg_id", &self.msg_id)
            .field(
                "reply_port",
                &self.reply_port.as_ref().map(|port| port.inner),
            )
            .finish()
    }
}

impl NewMessage<Server> {
    /// Replies to the client who sent this message with `reply_data`.
    ///
    /// This function will never block.
    ///
    /// This can only be called once, any futher calls will have no effect.
    ///
    /// If you do not want to respond to the sender, don't call this and instead drop this instance of [NewMessage].
    /// Well-behaving clients will not wait forever for a reply.
    pub fn reply(&mut self, reply_data: &[u8]) -> Result<(), Error> {
        if let Some(reply_port) = self.reply_port.take() {
            send_mach_message(&reply_port, reply_data, ReplyMode::Server)
        } else {
            Ok(())
        }
    }
}

struct ServerRecv<'a> {
    context: &'a Mutex<ServerDispatchContext>,
    source: &'a MachSource,
    max_msg_size_bytes: u32,
}

impl Future for ServerRecv<'_> {
    type Output = Result<NewMessage<Server>, Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut context = self.context.lock().unwrap();
        // Update this in case its changed since the last `listen` stream.
        context.max_msg_size_bytes = self.max_msg_size_bytes;

        match mem::replace(&mut context.poll_state, DispatchState::Idle) {
            DispatchState::Ready { mut message_batch } => {
                let oldest_msg = message_batch.pop_front().expect("incorrect future handler");

                if !message_batch.is_empty() {
                    // Put the state back, minus the oldest message, so that future polling
                    // prioritizes the backlogged messages and gets everything in order.
                    context.poll_state = DispatchState::Ready { message_batch };
                } else {
                    // If the listener has drained the batch queue then the dispatch source can start
                    // receiving ready events again. The next poll iteration will setup the next waker.
                    self.source.0.resume();
                }

                Poll::Ready(oldest_msg)
            }
            DispatchState::Idle => {
                // We either previously finished reading everything or this was the first time
                // we polled the dispatch source.
                context.poll_state = DispatchState::Polling(cx.waker().clone());
                Poll::Pending
            }
            DispatchState::Polling(mut waker) => {
                // If we were already waiting, just swap out the waker to match the new
                // executor context if needed.
                waker.clone_from(cx.waker());
                context.poll_state = DispatchState::Polling(waker);
                Poll::Pending
            }
        }
    }
}

const fn round_msg(mut msg_size: u32) -> u32 {
    // It is known at compile time that the value fits.
    #[expect(clippy::as_conversions)]
    if (msg_size & 0x3) != 0 {
        msg_size = (msg_size & !0x3) + size_of::<ffi::natural_t>() as u32;
    }

    msg_size
}

struct MessageBuffer(Vec<u8>);

impl MessageBuffer {
    unsafe fn read_header(&self) -> &ffi::mach_msg_header_t {
        debug_assert!(self.0.len() >= ffi::HEADER_SIZE);
        // SAFETY: The caller must ensure the buffer is initialized correctly.
        unsafe { &*(self.0.as_ptr().cast()) }
    }

    unsafe fn header(&mut self) -> &mut ffi::mach_msg_header_t {
        debug_assert!(self.0.len() >= ffi::HEADER_SIZE);
        // SAFETY: The caller must ensure the buffer is initialized correctly.
        unsafe { &mut *(self.0.as_mut_ptr().cast()) }
    }

    fn push_inline_data(&mut self, data: &[u8]) {
        self.0.extend(&data.len().to_ne_bytes());
        self.0.extend(data);
    }

    unsafe fn release_inner_references(&mut self) {
        // SAFETY: The caller must uphold that there is a valid message header in the buffer.
        // Even with no inner references this is fine.
        unsafe {
            let header = self.header();
            ffi::mach_msg_destroy(header)
        }
    }
}

enum ReplyMode<'a> {
    Server,
    Client {
        client_mode: ReplyInterest<'a>,
        timeout: Option<Duration>,
    },
}

enum ReplyInterest<'a> {
    SenderInterested(&'a ffi::MachPort),
    SenderUninterested,
}

/// Attempts to send `data` to `target_port`.
///
/// **Important**: This function is a blocking send. Mach ports have queues associated with them and, when full, sending
/// a message may block. The only exception to this case is when responding to a reply port (via send-once right) where the
/// limit is ignored and its delivered anyway.
///
/// See https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/mach_msg.html.
fn send_mach_message(
    target_port: &ffi::MachPort,
    data: &[u8],
    reply_mode: ReplyMode,
) -> Result<(), Error> {
    // If the message probably won't fit within a sane limit, reject it early for clearer errors.
    // For options to improve on this, see the documentation of `DEFAULT_MAX_MSG_SEND_SIZE_BYTES`.
    //
    // Make sure to round up to the next 4 bytes; `mach_msg` only supports aligned sizes.
    let original_size = data.len();
    let size = round_msg(
        (ffi::HEADER_SIZE + LENGTH_PREFIX_SIZE + original_size)
            .try_into()
            .map_err(|_| Error::MessageTooLarge)?,
    );
    if size > DEFAULT_MAX_MSG_SEND_SIZE_BYTES {
        return Err(Error::MessageTooLarge);
    }

    let mut timeout = None;

    // We checked that `size` fits within `u32::MAX` above.
    #[expect(clippy::as_conversions)]
    let mut message_buffer = MessageBuffer(Vec::with_capacity(size as usize));
    {
        // SAFETY: A zeroed header is valid and correct.
        let mut header: ffi::mach_msg_header_t = unsafe { MaybeUninit::zeroed().assume_init() };

        header.msgh_size = size;
        header.msgh_remote_port = target_port.inner;

        // The `msgh_local_port` field specifies an auxiliary port right, which is conventionally used as a reply port by the recipient of the message.
        // The field must carry a send right, a send-once right, `MACH_PORT_NULL`, or `MACH_PORT_DEAD`.
        header.msgh_local_port = ffi::MACH_PORT_NULL;

        match &reply_mode {
            // If we are sending to a reply port (and therefore don't have one of our own), then that means we only have a send-once right in `remote_port`. We need to release that, so move it into the kernel from our task.
            ReplyMode::Server => {
                header.msgh_bits = ffi::MACH_MSGH_BITS(ffi::MACH_MSG_TYPE_MOVE_SEND_ONCE, 0)
            }
            ReplyMode::Client {
                client_mode,
                timeout: desired_timeout,
            } => {
                // Otherwise if are not sending to a reply port, the `remote_port` we are sending to is the port we got from `launchd`. In these cases, we want to copy the send right `launchd` gave us so we can send multiple messages.
                match client_mode {
                    // Finally, if we are sending to a port from `launchd` and the client expects a response, then we need to give the receiver a send-once right to our reply port so we can get the response later.
                    ReplyInterest::SenderInterested(reply_port) => {
                        header.msgh_bits = ffi::MACH_MSGH_BITS(
                            ffi::MACH_MSG_TYPE_COPY_SEND,
                            ffi::MACH_MSG_TYPE_MAKE_SEND_ONCE,
                        );
                        header.msgh_local_port = reply_port.inner;
                    }
                    ReplyInterest::SenderUninterested => {
                        header.msgh_bits = ffi::MACH_MSGH_BITS(ffi::MACH_MSG_TYPE_COPY_SEND, 0)
                    }
                }

                timeout = *desired_timeout;
            }
        };

        // SAFETY: The buffer has enough capacity for a header and we always write a valid, initialized header of bytes into the buffer.
        unsafe {
            message_buffer
                .0
                .as_mut_ptr()
                .cast::<ffi::mach_msg_header_t>()
                .write(header);

            message_buffer.0.set_len(ffi::HEADER_SIZE)
        };
    }

    message_buffer.push_inline_data(data);

    let send_opts = match timeout {
        Some(_) => ffi::MACH_SEND_MSG | ffi::MACH_SEND_TIMEOUT,
        None => ffi::MACH_SEND_MSG,
    };

    // SAFETY: `message_buffer` has a correctly initialized header and is valid to write to, the options are correct, and the
    // other ports must be `MACH_PORT_NULL`.
    match unsafe {
        // The system doesn't support massive durations so just truncate ones that
        // are too high anyway.
        #[expect(clippy::as_conversions)]
        ffi::mach_msg(
            message_buffer.header(),
            send_opts,
            size,
            0,
            ffi::MACH_PORT_NULL,
            timeout.map(|dur| dur.as_millis() as u32).unwrap_or(0),
            ffi::MACH_PORT_NULL,
        )
    } {
        Ok(()) => Ok(()),
        Err(err) => {
            if matches!(reply_mode, ReplyMode::Server) {
                // Ensure the reply port is properly cleaned up if the client we were meant
                // to deliver it to died. This is the 2nd case this function is useful for, since
                // we have a send-once right that needs released. We could technically just release it ourselves
                // but if we ever add support for out-of-line data then this is the only way to cleanup.
                //
                // SAFETY: We wrote a valid message header into the buffer previously.
                unsafe { message_buffer.release_inner_references() };
                // At this point `target_port` is now `MACH_PORT_DEAD` but the deallocation function gracefully
                // handles this so we don't need to skip its `Drop`.
            }

            if err.code() == ffi::MACH_SEND_TIMED_OUT {
                Err(Error::FailedToSend)
            } else {
                // Any other error is a total failure. This could be an unexpected IPC failure or even the
                // owner of the mach port shutting down at a bad time. Either way, we can't retry.
                Err(Error::OsError(err))
            }
        }
    }
}

enum RecvMode {
    Server,
    ClientReply,
}

fn read_mach_message<Side>(
    port: &ffi::MachPort,
    max_msg_size: u32,
    recv_mode: RecvMode,
) -> Result<NewMessage<Side>, Error> {
    let mut current_size = 1024;

    // The size is known at compile time to fit in `usize`.
    #[expect(clippy::as_conversions)]
    let mut message_buffer = MessageBuffer(vec![0u8; current_size as usize]);
    {
        // SAFETY: All-zeros is a valid message header.
        let header = unsafe { message_buffer.header() };
        header.msgh_size = current_size
    }

    let (msg_id, reply_port) = loop {
        {
            // SAFETY: All-zeros is a valid message header.
            let header = unsafe { message_buffer.header() };
            // Reset any per-message state if we had to try again.
            header.msgh_bits = 0;
            // Cargo-culted from `CFMessagePort` despite it being overwritten upon receiving.
            header.msgh_local_port = port.inner;
            header.msgh_remote_port = ffi::MACH_PORT_NULL;
            header.msgh_id = 0;

            current_size = header.msgh_size;
        };

        // We need to cast these since some header types are interchangable with other use cases.
        #[expect(clippy::as_conversions)]
        let mut recv_options = ffi::MACH_RCV_MSG
            | ffi::MACH_RCV_LARGE
            | ffi::MACH_RCV_TRAILER_TYPE(ffi::MACH_MSG_TRAILER_FORMAT_0 as i32)
            | ffi::MACH_RCV_TRAILER_ELEMENTS(ffi::MACH_RCV_TRAILER_AV as i32);

        if matches!(recv_mode, RecvMode::Server) {
            recv_options |= ffi::MACH_RCV_TIMEOUT;
        }

        // SAFETY: `message_buffer` is configured with a valid header and is writable, the options are valid, the size is correct,
        // and the port we are receiving on always has a receive right.
        let ret = unsafe {
            ffi::mach_msg(
                message_buffer.header(),
                recv_options,
                0,
                current_size,
                port.inner,
                0, // As we received a signal this was readable, we expect something to be present
                ffi::MACH_PORT_NULL,
            )
        };

        match ret {
            // Validate the message contents before doing anything else with them.
            Ok(()) => {
                // SAFETY: The receive call succeeded, so there's always a valid message header in the buffer.
                let msgh_bits = unsafe { message_buffer.read_header().msgh_bits };
                // If we got a message with either:
                // - A body with non-POD contents
                // - Not the correct reply port type.
                if msgh_bits & ffi::MACH_MSGH_BITS_COMPLEX != 0 {
                    // If we got a message , something we didn't expect sent us a message and its not
                    // safe to process it further. Ensure that the system has a chance to free any complex data to prevent leaking
                    // resources: https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/libsyscall/mach/mach_msg.c#L392.
                    // It only frees the resources behind descriptors, not our buffer.
                    //
                    // This is unneeded in the case of inline data/simple messages.
                    //
                    // SAFETY: The receive call succeeded, so there's always a valid header in the buffer.
                    unsafe {
                        message_buffer.release_inner_references();
                    }
                    return Err(Error::CorruptMessage);
                }

                // SAFETY: The receive call succeeded, so there's always a valid header in the buffer.
                let header = unsafe { message_buffer.read_header() };

                let msg_id = header.msgh_id;

                // Per the Mach specification "Each send-once right generated guarantees the receipt of a single message, either a
                // message sent to that send-once right or, if the send-once right is in any way destroyed, a send-once notification"
                //
                // If the server ignores and deallocates a client's reply port, which could be a send-once right, the kernel
                // steps in and ensures we are given an instance of `mach_send_once_notification_t` so we don't block forever
                // waiting on a now-impossible event.
                //
                // Specifically check if there was no inline data to prevent a conflict of `msg_id` being defined the same
                // as `MACH_NOTIFY_SEND_ONCE` by an end user. We already checked there were no descriptors, so this means
                // it was a proper kernel notification or a completely empty message which is basically the same as far as
                // this is concerned. We _could_ check the trailer format to see it is != what we requested but its not clear
                // this would make a difference.
                #[expect(clippy::as_conversions)]
                if matches!(recv_mode, RecvMode::ClientReply)
                    && msg_id == ffi::MACH_NOTIFY_SEND_ONCE
                    && header.msgh_size == ffi::HEADER_SIZE as u32
                    && current_size >= ffi::FORMAT_0_SIZE
                {
                    return Err(Error::NoReply);
                }

                let reply_port = if header.msgh_remote_port != ffi::MACH_PORT_NULL {
                    Some(ffi::MachPort {
                        inner: header.msgh_remote_port,
                        // This port is either `TYPE_PORT_SEND_ONCE` or `TYPE_PORT_SEND`, so we only need
                        // to release the reference count and the kernel handles the rest.
                        release: ffi::mach_port_deallocate,
                    })
                } else {
                    None
                };

                current_size = header.msgh_size;

                break (msg_id, reply_port);
            }
            Err(e) if e.code() == ffi::MACH_RCV_TOO_LARGE => {
                let next_size = {
                    // SAFETY: The receive call needs to write in the expected size, so there's always a valid header in the buffer.
                    let header = unsafe { message_buffer.header() };
                    let next_size = round_msg(header.msgh_size + ffi::MAX_TRAILER_SIZE);
                    header.msgh_size = next_size;
                    next_size
                };

                // Validate that size stays within a reasonable amount to prevent being forcibly
                // killed due to OOM conditions.
                if next_size > max_msg_size {
                    return Err(Error::MessageTooLarge);
                }

                // A message sent through the kernel can't be any larger then `u32::MAX`, so its impossible for this to overflow.
                #[expect(clippy::as_conversions)]
                message_buffer.0.resize(next_size as usize, 0);
                continue;
            }
            Err(e) => return Err(Error::OsError(e)),
        }
    };

    // A message sent through the kernel can't be any larger then `u32::MAX`, so its impossible for this to overflow.
    #[expect(clippy::as_conversions)]
    message_buffer
        .0
        .resize((current_size + ffi::MAX_TRAILER_SIZE) as usize, 0);

    drop(message_buffer.0.drain(..ffi::HEADER_SIZE));

    let Some(data_length) = message_buffer
        .0
        .drain(..LENGTH_PREFIX_SIZE)
        .as_slice()
        .try_into()
        .ok()
        .map(usize::from_ne_bytes)
    else {
        return Err(Error::CorruptMessage);
    };

    // `msgh_size` is the header, descriptors, and inline data. We checked above that there were no
    // descriptors in the body so the end of the message data will be where the trailer
    //
    // The lengths are known at compile time to fit into a `u32`.
    #[expect(clippy::as_conversions)]
    let trailer_start =
        round_msg(current_size - ffi::HEADER_SIZE as u32 - LENGTH_PREFIX_SIZE as u32) as usize;

    let trailer_contents = message_buffer.0.drain(trailer_start..);
    let trailer = trailer_contents.as_slice();

    // SAFETY: There is always a minimal trailer on all mach messages and the system gave us
    // a valid pointer to it.
    let base_trailer = unsafe { &*trailer.as_ptr().cast::<ffi::mach_msg_trailer_t>() };
    if base_trailer.msgh_trailer_type != ffi::MACH_MSG_TRAILER_FORMAT_0
        || base_trailer.msgh_trailer_size < ffi::AUDIT_TRAILER_SIZE
    {
        return Err(Error::CorruptMessage);
    }

    // SAFETY: We validated that the mach trailer was large enough to contain an audit token.
    let audit_trailer = unsafe { &*trailer.as_ptr().cast::<ffi::mach_msg_audit_trailer_t>() };
    let audit_token = audit_trailer.msgh_audit;

    // Remove the trailer bytes from the buffer so only the sent user data remains.
    // This also drops any unused buffer capacity the receive call didn't need.
    drop(trailer_contents);

    // Finally, remove any alignment padding zeros from the buffer.
    drop(message_buffer.0.drain(data_length..));

    // By this stage we have taken the original message of [header, inline data, trailer, ...unused zeros]
    // and removed the header, trailer, and anything after the trailer. It now looks like `[..., inline data, ...]`.
    Ok(NewMessage {
        data: message_buffer.0,
        msg_id,
        sender_identity: audit_token,
        reply_port,
        _side: PhantomData,
    })
}
