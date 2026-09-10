petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store","bloom:chain"]),
    read: |ctx:&petal::Ctx| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::read_transaction(wallet,id)
    },
    write: |ctx:&petal::Ctx,body:&[u8]| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        let value:serde_json::Value=match serde_json::from_slice(body){Ok(v)=>v,Err(e)=>return petal::error(-3,format!("invalid JSON: {e}"))};
        let safe_id=match value.get("safe_id").and_then(serde_json::Value::as_str){Some(v)=>v,None=>return petal::error(-3,"draft requires safe_id")};
        let transaction=match value.get("transaction"){Some(v)=>match serde_json::to_vec(v){Ok(v)=>v,Err(e)=>return petal::error(-3,e.to_string())},None=>return petal::error(-3,"draft requires transaction")};
        crate::create_transaction(wallet,safe_id,id,&transaction)
    }
);
