petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store","bloom:tx.outbox"]),
    read: |_ctx:&petal::Ctx| petal::DispatchResponse::Read(b"write any body to forget this transaction and its held signature\n".to_vec()),
    write: |ctx:&petal::Ctx,_body:&[u8]| {
        let wallet=match petal::wallet_param(ctx){Ok(v)=>v,Err(e)=>return e};
        let index=match petal::param(ctx,"index"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::discard(wallet,index,id)
    }
);
