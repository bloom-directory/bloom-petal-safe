petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::read_json_value(&serde_json::json!({
        "petal":"safe",
        "status":"ok",
        "safe_versions":["1.3.0","1.4.1","1.5.0"],
        "operations":["bind","inspect","call","native_transfer","erc20_transfer","call_only_batch","transaction_builder","create","create2","reject","confirm","propose","execute","reconcile"],
        "security":{"refunds":"disabled","delegatecall":["MultiSendCallOnly","CreateCall"],"safe_administration":"rejected","future_nonces":"rejected"}
    }))
);
