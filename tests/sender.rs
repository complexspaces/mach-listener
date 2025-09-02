use futures_util::StreamExt;
use mach_listener::*;

mod utils;

thread_local! {
    static TEST_ID: usize = const { 0 };
}

const TEST_MSG: &[u8] = b"+++hello_world+++";

#[test]
fn send_with_no_reply() {
    const EXPECTED_MESSAGES: usize = 6;

    let server_name = TEST_ID.with(|id| {
        let id = core::ptr::addr_of!(id) as usize as u64;
        utils::server_name(id)
    });

    let mut server = Server::register(&server_name).unwrap();

    let (sender_done, mut wait_for_sender) = tokio::sync::mpsc::unbounded_channel::<()>();
    std::thread::spawn(move || {
        let mut client = Client::connect(&server_name).unwrap();
        for n in 0..=EXPECTED_MESSAGES {
            println!("sending #{n}");
            client.send(TEST_MSG).unwrap();
        }
        sender_done.send(()).unwrap();
    });

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut incoming_messages = std::pin::pin!(server.listen());

        let mut received = 0;

        loop {
            tokio::select! {
                biased;

                new_msg = incoming_messages.next() => {
                    let new_msg = new_msg.unwrap().unwrap();
                    assert_eq!(new_msg.data, TEST_MSG, "server message corrupt");
                    assert_eq!(new_msg.msg_id, 0, "unexpected msg_id");
                    received += 1;
                    if received == EXPECTED_MESSAGES {
                        break;
                    }
                }

                _sender_done = wait_for_sender.recv() => {},
            }
        }
    });
}

#[test]
fn send_with_reply_but_ignored() {
    let server_name = TEST_ID.with(|id| {
        let id = core::ptr::addr_of!(id) as usize as u64;
        utils::server_name(id)
    });

    let mut server = Server::register(&server_name).unwrap();

    let (sender_done, mut wait_for_sender) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut client = Client::connect(&server_name).unwrap();
        let err = client.send_with_reply(TEST_MSG).unwrap_err();
        sender_done.send(err).unwrap();
    });

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut incoming_messages = std::pin::pin!(server.listen());

        let mut received = false;

        loop {
            tokio::select! {
                new_msg = incoming_messages.next() => {
                    let new_msg = new_msg.unwrap().unwrap();
                    assert_eq!(new_msg.data, TEST_MSG, "server message corrupt");
                    assert_eq!(new_msg.msg_id, 0, "unexpected msg_id");
                    received = true;
                }

                sender_done = wait_for_sender.recv(), if received => {
                    assert_eq!(sender_done, Some(Error::NoReply));
                    break;
                },
            }
        }
    });
}
