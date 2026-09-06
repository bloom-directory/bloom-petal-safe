petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::DispatchResponse::Read(include_bytes!("../../../../../../README.md").to_vec())
);
