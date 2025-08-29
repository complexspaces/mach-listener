use futures_util::{StreamExt, future};
use mach_listener::*;
use std::hash::BuildHasher;

mod utils;

const EXPECTED_MESSAGES: u8 = 3;

fn main() {
    let current_args = std::env::args().collect::<Vec<String>>();
    let child_data: Option<u64> = current_args
        .iter()
        .find_map(|arg| arg.strip_prefix("--child-data="))
        .map(|data| data.parse().unwrap());

    // Ensure this isn't an even number of bytes. This tests that the mach header size
    // alignment is correctly handled.
    let data_prefix = b"any bytes \0 work here ++++++:";

    if child_data.is_none() {
        println!("starting multi-process send/recv test...");
        // Create a per-test unique checksum to keep the test mach service name unique and
        // to make it infeasible that any garbage bytes that just happen to look like our test
        // data are not caught as incorrect.
        let prefix_hasher = std::hash::RandomState::new();
        let prefix_checksum = prefix_hasher.hash_one(data_prefix);

        let server_name = utils::server_name(prefix_checksum);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut server = Server::register(&server_name).unwrap();
            let (stop_handle, abortable) = future::AbortHandle::new_pair();

            let receiver_task = runtime.spawn(async move {
                let mut received = 0;
                let mut incoming_messages =
                    std::pin::pin!(future::Abortable::new(server.listen(), abortable));

                while let Some(msg_result) = incoming_messages.next().await {
                    let mut msg = msg_result.unwrap();
                    // println!("Received message #{received}");

                    assert_eq!(msg.msg_id, 0, "unexpected server mach msg_id");

                    let prefix = msg.data.drain(..data_prefix.len());
                    assert_eq!(prefix.as_slice(), data_prefix, "server message corrupted");
                    drop(prefix);

                    let msg_num = msg.data.remove(0);
                    assert_eq!(
                        msg_num, received,
                        "server message out of order or corrupted"
                    );

                    let checksum = msg.data.drain(..);
                    assert_eq!(
                        checksum.as_slice(),
                        &prefix_hasher.hash_one(data_prefix).to_ne_bytes(),
                        "server message very corrupted"
                    );
                    drop(checksum);

                    assert!(
                        msg.data.is_empty(),
                        "unexpected server buffer space remaining"
                    );

                    // We don't need to verify the checksum again, the client uses the same
                    // receive path as the server.
                    let mut reply_data = Vec::from(data_prefix);
                    reply_data.push(received);
                    msg.reply(&reply_data).unwrap();

                    received += 1;
                }

                received
            });

            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
            let child_extra_arg = format!("--child-data={prefix_checksum}");

            let child = child.arg(child_extra_arg).args(current_args.iter().skip(1));

            let mut child = child.spawn().unwrap();
            child.wait().await.unwrap();
            stop_handle.abort();

            let received = receiver_task.await.unwrap();
            assert_eq!(received, EXPECTED_MESSAGES);
            println!("Test ok");
        });
    } else {
        let prefix_checksum = child_data.unwrap();
        let mut client = Client::connect(&utils::server_name(prefix_checksum)).unwrap();

        for n in 0..EXPECTED_MESSAGES {
            let mut data = Vec::from(data_prefix);
            data.push(n);
            data.extend_from_slice(&prefix_checksum.to_ne_bytes());

            // eprintln!("Sending message {n}...");
            let mut reply = client.send_with_reply(&data).unwrap();
            // eprintln!("Received reply to message #{n}");

            assert_eq!(reply.msg_id, 0, "unexpected client mach msg_id");

            let prefix = reply.data.drain(..data_prefix.len());
            assert_eq!(prefix.as_slice(), data_prefix, "client message corrupted");
            drop(prefix);

            let msg_num = reply.data.remove(0);
            assert_eq!(n, msg_num, "client message out of order or corrupted");

            assert!(
                reply.data.is_empty(),
                "unexpected client buffer space remaining"
            );
        }
    }
}
