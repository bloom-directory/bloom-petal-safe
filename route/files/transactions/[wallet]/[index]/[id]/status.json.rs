petal::route_file!(
    spec: petal::chain_read_spec().caps(&["bloom:store","bloom:chain","bloom:tx.outbox"]),
    read: |ctx:&petal::Ctx| {
        let wallet=match petal::wallet_param(ctx){Ok(v)=>v,Err(e)=>return e};
        let index=match petal::param(ctx,"index"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::read_transaction(wallet,index,id)
    }
);
