//! Child processes belong to one long-lived backend thread, never an RPC peer.
use super::{Backend, Operation, Outcome};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;

enum Call {
    Execute(Operation),
    Reap,
    Shutdown,
}

pub(super) struct Worker {
    requests: Option<SyncSender<Call>>,
    replies: Receiver<Result<Outcome, String>>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub(super) fn start(mut backend: Box<dyn Backend>) -> Result<Self, String> {
        let (requests, incoming) = mpsc::sync_channel(0);
        let (replies, outgoing) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("netorch-backend".into())
            .spawn(move || {
                let mut stopped = false;
                while let Ok(call) = incoming.recv() {
                    let result = match call {
                        Call::Execute(operation) => backend.execute(operation),
                        Call::Reap => backend.reap().map(|()| Outcome::Unit),
                        Call::Shutdown => {
                            stopped = true;
                            backend.shutdown().map(|()| Outcome::Unit)
                        }
                    };
                    if replies.send(result).is_err() || stopped {
                        break;
                    }
                }
                if !stopped {
                    let _ = backend.shutdown();
                }
            })
            .map_err(|_| "Cannot start the connection backend thread")?;
        Ok(Self {
            requests: Some(requests),
            replies: outgoing,
            thread: Some(thread),
        })
    }

    fn call(&mut self, call: Call) -> Result<Outcome, String> {
        self.requests
            .as_ref()
            .ok_or("The connection backend has stopped")?
            .send(call)
            .map_err(|_| "The connection backend is unavailable")?;
        self.replies
            .recv()
            .map_err(|_| "The connection backend did not answer")?
    }
}

impl Backend for Worker {
    fn execute(&mut self, operation: Operation) -> Result<Outcome, String> {
        self.call(Call::Execute(operation))
    }

    fn reap(&mut self) -> Result<(), String> {
        self.call(Call::Reap).map(|_| ())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        let result = self.call(Call::Shutdown).map(|_| ());
        self.requests.take();
        let joined = self.thread.take().map_or(Ok(()), |thread| {
            thread
                .join()
                .map_err(|_| "The connection backend failed".to_string())
        });
        result.and(joined)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
