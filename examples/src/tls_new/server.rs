use std::{error::Error, fs::File, io::BufReader, sync::Arc};

use tokio_rustls::rustls::{
    crypto::ring,
    pki_types::CertificateDer,
    server::{ResolvesServerCert, WebPkiClientVerifier},
    sign::{CertifiedKey, SigningKey},
    RootCertStore, ServerConfig,
};

#[derive(Debug)]
struct CustomCertResolver(Arc<CertifiedKey>);

impl CustomCertResolver {
    pub fn new(cert_chain: Vec<CertificateDer<'static>>, private_key: Arc<dyn SigningKey>) -> Self {
        let certified_key = CertifiedKey::new(cert_chain, private_key).into();
        Self(certified_key)
    }
}

impl ResolvesServerCert for CustomCertResolver {
    fn resolve(
        &self,
        _client_hello: tokio_rustls::rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<CertifiedKey>> {
        dbg!(Some(self.0.clone()))
    }
}

pub mod pb {
    tonic::include_proto!("grpc.examples.unaryecho");
}

use pb::{EchoRequest, EchoResponse};
use tonic::{
    transport::{Server, ServerTlsConfig},
    Request, Response, Status,
};
type EchoResult<T> = Result<Response<T>, Status>;

#[derive(Default)]
pub struct EchoServer;

#[tonic::async_trait]
impl pb::echo_server::Echo for EchoServer {
    async fn unary_echo(&self, request: Request<EchoRequest>) -> EchoResult<EchoResponse> {
        let message = request.into_inner().message;
        Ok(Response::new(EchoResponse { message }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "[::1]:50001".parse().unwrap();
    let server = EchoServer::default();
    let data_dir = std::path::PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "data"]);

    let crypto_provider = ring::default_provider();
    let cert_chain = {
        let file = File::open(data_dir.join("tls/server.pem"))?;
        let mut buf = BufReader::new(file);
        rustls_pemfile::certs(&mut buf).collect::<Result<Vec<_>, _>>()?
    };

    let pkey = {
        let file = File::open(data_dir.join("tls/server.key"))?;
        let mut buf = BufReader::new(file);
        crypto_provider
            .key_provider
            .load_private_key(rustls_pemfile::private_key(&mut buf)?.unwrap())?
    };

    let cert_resolver: Arc<dyn ResolvesServerCert> =
        Arc::new(CustomCertResolver::new(cert_chain, pkey));

    let roots = {
        let mut root_certs = RootCertStore::empty();
        let file = File::open(data_dir.join("tls/ca.pem"))?;
        let mut buf = BufReader::new(file);
        root_certs.add_parsable_certificates(
            rustls_pemfile::certs(&mut buf).collect::<Result<Vec<_>, _>>()?,
        );
        root_certs
    };

    // let client_cerifier = WebPkiClientVerifier::builder(roots.into()).build()?.into();

    let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()?
        // .with_client_cert_verifier(client_cerifier)
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    server_config.alpn_protocols = vec![b"h2".to_vec()];

    let server_config = ServerTlsConfig::default().server_config(server_config.into());

    Server::builder()
        .tls_config(server_config)?
        .add_service(pb::echo_server::EchoServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
