petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store"]),
    read: |_ctx:&petal::Ctx| petal::DispatchResponse::Read(b"write-only Safe Transaction Service API key\n".to_vec()),
    write: |ctx:&petal::Ctx,body:&[u8]| {
        let wallet=match petal::wallet_param(ctx){Ok(v)=>v,Err(e)=>return e};
        let index=match petal::param(ctx,"index"){Ok(v)=>v,Err(e)=>return e};
        let safe_id=match petal::param(ctx,"safe_id"){Ok(v)=>v,Err(e)=>return e};
        crate::set_service_key(wallet,index,safe_id,body)
    }
);
