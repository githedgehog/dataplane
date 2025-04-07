// This file is @generated by prost-build.
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct GetConfigRequest {}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateConfigRequest {
    #[prost(message, optional, tag = "1")]
    pub config: ::core::option::Option<GatewayConfig>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateConfigResponse {
    #[prost(enumeration = "Error", tag = "1")]
    pub error: i32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct GetConfigGenerationRequest {}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct GetConfigGenerationResponse {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Subnet {
    #[prost(string, tag = "1")]
    pub cidr: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Vpc {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub vni: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "4")]
    pub subnets: ::prost::alloc::vec::Vec<Subnet>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Device {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(string, tag = "2")]
    pub ipaddr: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub pciaddr: ::prost::alloc::string::String,
    #[prost(enumeration = "IfType", tag = "5")]
    pub r#type: i32,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeeringIPs {
    #[prost(string, tag = "1")]
    pub cidr: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub not: ::prost::alloc::string::String,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeeringAs {
    #[prost(string, tag = "1")]
    pub cidr: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub not: ::prost::alloc::string::String,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeeringEntry {
    #[prost(message, repeated, tag = "1")]
    pub r#as: ::prost::alloc::vec::Vec<PeeringAs>,
    #[prost(message, repeated, tag = "2")]
    pub ips: ::prost::alloc::vec::Vec<PeeringIPs>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Peering {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(map = "string, message", tag = "2")]
    pub entries: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        PeeringEntry,
    >,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct BgpAddressFamilyOptions {
    #[prost(bool, tag = "1")]
    pub redistribute_connected: bool,
    #[prost(bool, tag = "2")]
    pub redistribute_static: bool,
    #[prost(bool, tag = "3")]
    pub send_community: bool,
    #[prost(bool, tag = "4")]
    pub advertise_all_vni: bool,
    #[prost(bool, tag = "5")]
    pub ipv4_enable: bool,
    #[prost(bool, tag = "6")]
    pub l2vpn_enable: bool,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BgpNeighbor {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub remote_asn: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "3")]
    pub address_families: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteMap {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "2")]
    pub match_prefix_lists: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "3")]
    pub action: ::prost::alloc::string::String,
    #[prost(uint32, tag = "4")]
    pub sequence: u32,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouterConfig {
    #[prost(string, tag = "1")]
    pub asn: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub router_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub neighbors: ::prost::alloc::vec::Vec<BgpNeighbor>,
    #[prost(message, repeated, tag = "4")]
    pub options: ::prost::alloc::vec::Vec<BgpAddressFamilyOptions>,
    #[prost(message, repeated, tag = "5")]
    pub route_maps: ::prost::alloc::vec::Vec<RouteMap>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Vrf {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub router: ::core::option::Option<RouterConfig>,
    #[prost(message, optional, tag = "3")]
    pub vpc: ::core::option::Option<Vpc>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GatewayConfig {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    #[prost(message, repeated, tag = "2")]
    pub devices: ::prost::alloc::vec::Vec<Device>,
    #[prost(message, repeated, tag = "3")]
    pub peerings: ::prost::alloc::vec::Vec<Peering>,
    #[prost(message, repeated, tag = "4")]
    pub vrfs: ::prost::alloc::vec::Vec<Vrf>,
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Error {
    None = 0,
    ValidationFailed = 1,
    ApplyFailed = 2,
    UnknownError = 3,
}
impl Error {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::None => "ERROR_NONE",
            Self::ValidationFailed => "ERROR_VALIDATION_FAILED",
            Self::ApplyFailed => "ERROR_APPLY_FAILED",
            Self::UnknownError => "ERROR_UNKNOWN_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ERROR_NONE" => Some(Self::None),
            "ERROR_VALIDATION_FAILED" => Some(Self::ValidationFailed),
            "ERROR_APPLY_FAILED" => Some(Self::ApplyFailed),
            "ERROR_UNKNOWN_ERROR" => Some(Self::UnknownError),
            _ => None,
        }
    }
}
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum IfType {
    Uplink = 0,
    Management = 1,
    Vxlan = 2,
}
impl IfType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Uplink => "IF_TYPE_UPLINK",
            Self::Management => "IF_TYPE_MANAGEMENT",
            Self::Vxlan => "IF_TYPE_VXLAN",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "IF_TYPE_UPLINK" => Some(Self::Uplink),
            "IF_TYPE_MANAGEMENT" => Some(Self::Management),
            "IF_TYPE_VXLAN" => Some(Self::Vxlan),
            _ => None,
        }
    }
}
/// Generated client implementations.
pub mod config_service_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value,
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct ConfigServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ConfigServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ConfigServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ConfigServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::Body>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::Body>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::Body>,
            >>::Error: Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            ConfigServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn get_config(
            &mut self,
            request: impl tonic::IntoRequest<super::GetConfigRequest>,
        ) -> std::result::Result<tonic::Response<super::GatewayConfig>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/config.ConfigService/GetConfig",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("config.ConfigService", "GetConfig"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_config_generation(
            &mut self,
            request: impl tonic::IntoRequest<super::GetConfigGenerationRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetConfigGenerationResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/config.ConfigService/GetConfigGeneration",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("config.ConfigService", "GetConfigGeneration"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn update_config(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdateConfigRequest>,
        ) -> std::result::Result<
            tonic::Response<super::UpdateConfigResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/config.ConfigService/UpdateConfig",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("config.ConfigService", "UpdateConfig"));
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod config_service_server {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value,
    )]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with ConfigServiceServer.
    #[async_trait]
    pub trait ConfigService: std::marker::Send + std::marker::Sync + 'static {
        async fn get_config(
            &self,
            request: tonic::Request<super::GetConfigRequest>,
        ) -> std::result::Result<tonic::Response<super::GatewayConfig>, tonic::Status>;
        async fn get_config_generation(
            &self,
            request: tonic::Request<super::GetConfigGenerationRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetConfigGenerationResponse>,
            tonic::Status,
        >;
        async fn update_config(
            &self,
            request: tonic::Request<super::UpdateConfigRequest>,
        ) -> std::result::Result<
            tonic::Response<super::UpdateConfigResponse>,
            tonic::Status,
        >;
    }
    #[derive(Debug)]
    pub struct ConfigServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T> ConfigServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for ConfigServiceServer<T>
    where
        T: ConfigService,
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/config.ConfigService/GetConfig" => {
                    #[allow(non_camel_case_types)]
                    struct GetConfigSvc<T: ConfigService>(pub Arc<T>);
                    impl<
                        T: ConfigService,
                    > tonic::server::UnaryService<super::GetConfigRequest>
                    for GetConfigSvc<T> {
                        type Response = super::GatewayConfig;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetConfigRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as ConfigService>::get_config(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetConfigSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/config.ConfigService/GetConfigGeneration" => {
                    #[allow(non_camel_case_types)]
                    struct GetConfigGenerationSvc<T: ConfigService>(pub Arc<T>);
                    impl<
                        T: ConfigService,
                    > tonic::server::UnaryService<super::GetConfigGenerationRequest>
                    for GetConfigGenerationSvc<T> {
                        type Response = super::GetConfigGenerationResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetConfigGenerationRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as ConfigService>::get_config_generation(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetConfigGenerationSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/config.ConfigService/UpdateConfig" => {
                    #[allow(non_camel_case_types)]
                    struct UpdateConfigSvc<T: ConfigService>(pub Arc<T>);
                    impl<
                        T: ConfigService,
                    > tonic::server::UnaryService<super::UpdateConfigRequest>
                    for UpdateConfigSvc<T> {
                        type Response = super::UpdateConfigResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UpdateConfigRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as ConfigService>::update_config(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = UpdateConfigSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        let mut response = http::Response::new(
                            tonic::body::Body::default(),
                        );
                        let headers = response.headers_mut();
                        headers
                            .insert(
                                tonic::Status::GRPC_STATUS,
                                (tonic::Code::Unimplemented as i32).into(),
                            );
                        headers
                            .insert(
                                http::header::CONTENT_TYPE,
                                tonic::metadata::GRPC_CONTENT_TYPE,
                            );
                        Ok(response)
                    })
                }
            }
        }
    }
    impl<T> Clone for ConfigServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    /// Generated gRPC service name
    pub const SERVICE_NAME: &str = "config.ConfigService";
    impl<T> tonic::server::NamedService for ConfigServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
