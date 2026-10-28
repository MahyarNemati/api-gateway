//! Body type aliases and helpers shared across the proxy pipeline.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Body, Frame, SizeHint};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

pub fn full(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pin_project_lite::pin_project! {
    /// Keeps `guard` alive until the wrapped body is fully streamed or dropped.
    pub struct Guarded<B, G> {
        #[pin]
        inner: B,
        guard: Option<G>,
    }
}

impl<B, G> Guarded<B, G> {
    pub fn new(inner: B, guard: G) -> Self {
        Self {
            inner,
            guard: Some(guard),
        }
    }
}

impl<B: Body, G> Body for Guarded<B, G> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let res = this.inner.poll_frame(cx);
        if matches!(res, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            this.guard.take();
        }
        res
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
