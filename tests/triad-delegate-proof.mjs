// Real compiled Petal -> Machine -> Broker -> Signer integration on Anvil.
// The Transaction Service is a deliberately small authenticated fixture, not
// Safe's production service. A Cloudflare quick tunnel supplies trusted HTTPS
// without weakening Machine TLS validation or changing the user's trust store.
import assert from "node:assert/strict"
import { execFile, spawn } from "node:child_process"
import { createServer } from "node:http"
import { createServer as createNetServer, connect } from "node:net"
import { lookup, resolve4 } from "node:dns/promises"
import { get as httpsGet } from "node:https"
import { mkdtemp, mkdir, readFile, writeFile, access, unlink } from "node:fs/promises"
import { openSync, readFileSync } from "node:fs"
import { basename, dirname, resolve, join } from "node:path"
import { fileURLToPath } from "node:url"
import { promisify } from "node:util"
import { randomBytes, createHash } from "node:crypto"
import ethersPackage from "ethers"

const { Contract, ContractFactory, Wallet, providers, utils } = ethersPackage
const run = promisify(execFile)
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const machineRepo = process.env.BLOOM_MACHINE_REPO || resolve(repo, "../bloom")
const brokerRepo = process.env.BLOOM_BROKER_REPO || resolve(repo, "../bloom-broker")
const signerRepo = process.env.BLOOM_SIGNER_REPO || resolve(repo, "../bloom-signer")
const machine = process.env.BLOOM_INTEGRATION_MACHINE_BIN || join(machineRepo, "target/debug/bloom")
const broker = process.env.BLOOM_INTEGRATION_BROKER_BIN || join(brokerRepo, "target/debug/bloom-broker")
const signer = process.env.BLOOM_INTEGRATION_SIGNER_BIN || join(signerRepo, "target/debug/bloom-signer")
const driver = process.env.BLOOM_INTEGRATION_DEBUG_DRIVER_BIN || join(brokerRepo, "target/debug/bloom-broker-debug-driver")
const launcher = process.env.BLOOM_TRIAD_DEV_LAUNCHER || join(machineRepo, "scripts/triad-dev-launch.sh")
const work = await mkdtemp(join(process.env.BLOOM_TEST_TMP_DIR || "/tmp", "safe-e2e."))
const developerRoot = join(work, "d")
const machineHome = join(developerRoot, "machine")
const logs = join(work, "logs")
await mkdir(machineHome, { recursive: true, mode: 0o700 })
await mkdir(logs, { mode: 0o700 })
const children = []
const interruption = new AbortController()
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => {
  interruption.abort(new Error(`Interrupted by ${signal}`))
  for (const child of [...children].reverse()) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM")
  }
})
let fixture
let provider
let tunnelProxy
let count = 0
const authSeed = "safe-delegate-disposable-authenticator"
const apiKey = randomBytes(32).toString("hex")
const mnemonicFile = join(work, "disposable-mnemonic.txt")
const evidence = { scope: "Compiled Safe Petal and real local Triad; authenticated Transaction Service fixture behind ephemeral HTTPS tunnel; software WebAuthn test authenticator", binaries: {}, checks: [] }
const note = text => console.log(`[delegate triad] ${text}`)
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const exists = async path => { try { await access(path); return true } catch { return false } }
const freePort = () => new Promise((resolve, reject) => {
  const server = createNetServer()
  server.on("error", reject)
  server.listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)) })
})
const start = (binary, args, name, env = {}) => {
  interruption.signal.throwIfAborted()
  const fd = openSync(join(logs, `${name}.log`), "w", 0o600)
  const child = spawn(binary, args, { cwd: repo, stdio: ["ignore", fd, fd], env: { ...process.env, ...env } })
  children.push(child)
  return child
}
const until = async (description, fn, ms = 60000) => {
  const deadline = Date.now() + ms
  let last
  while (Date.now() < deadline) {
    interruption.signal.throwIfAborted()
    try { const value = await fn(); if (value) return value } catch (error) { last = error }
    await sleep(100)
  }
  throw new Error(`Timed out: ${description}${last ? ` (${last.message})` : ""}`)
}
const command = async (binary, args, options = {}) => {
  const { stdout, stderr } = await run(binary, args, { cwd: repo, timeout: 120000, maxBuffer: 4 * 1024 * 1024, signal: interruption.signal, ...options })
  return stdout || stderr
}
const cli = (...args) => command("bash", ["-c", 'source "$1"; shift; exec "$@"', "safe-test", join(logs, "triad.env"), machine, "--home", machineHome, ...args])
const vcat = path => cli("vfs", "cat", path)
const vjson = async path => JSON.parse(await vcat(path))
const vwrite = (path, value = "") => cli("vfs", "write", path, "--data", typeof value === "string" ? value : JSON.stringify(value))
const complete = async (url, extra = []) => JSON.parse(await command(driver, ["complete", url, authSeed, "--sign-count", String(++count), ...extra]))
const launchField = (text, field) => {
  const value = text.match(new RegExp(`^${field}: (.+)$`, "m"))?.[1]
  assert(value, `Missing ${field} in ceremony launch`)
  return value
}
const refused = async (description, fn, expected) => {
  let diagnostic = ""
  try { await fn() } catch (error) { diagnostic = `${error.stderr || ""}\n${error.stdout || ""}` }
  // The VFS projects Petal denials as POSIX errors rather than returning
  // private handler diagnostics. Positive steps and state assertions below
  // distinguish the intended refusal from an unrelated setup failure.
  assert.match(diagnostic, new RegExp(`${expected.source}|permission denied|[Ii]nput/output error`), description)
  evidence.checks.push(description)
}
const zero = "0x0000000000000000000000000000000000000000"
const recipient = "0x4000000000000000000000000000000000000000"
const types = { SafeTx: [
  {name:"to",type:"address"},{name:"value",type:"uint256"},{name:"data",type:"bytes"},{name:"operation",type:"uint8"},
  {name:"safeTxGas",type:"uint256"},{name:"baseGas",type:"uint256"},{name:"gasPrice",type:"uint256"},{name:"gasToken",type:"address"},
  {name:"refundReceiver",type:"address"},{name:"nonce",type:"uint256"}
] }
try {
  for (const [name, binary, checkout] of [["machine", machine, machineRepo], ["broker", broker, brokerRepo], ["signer", signer, signerRepo], ["debug_driver", driver, brokerRepo]]) {
    await access(binary)
    const commit = (await command("git", ["-C", checkout, "rev-parse", "HEAD"])).trim()
    const dirty = (await command("git", ["-C", checkout, "status", "--porcelain"])).trim() !== ""
    const trackedDirty = (await command("git", ["-C", checkout, "diff", "--name-only", "HEAD"])).trim() !== ""
    evidence.binaries[name] = { path: binary, checkout_commit: commit, checkout_dirty: dirty, tracked_source_dirty: trackedDirty, sha256: createHash("sha256").update(readFileSync(binary)).digest("hex") }
  }
  await command("anvil", ["--version"])
  await command(process.env.CLOUDFLARED_BIN || "cloudflared", ["--version"])
  note(`Disposable state: ${work}`)
  const rpcPort = await freePort()
  const rpc = `http://127.0.0.1:${rpcPort}`
  start("anvil", ["--port", String(rpcPort), "--host", "127.0.0.1", "--chain-id", "31337", "--silent"], "anvil")
  provider = new providers.JsonRpcProvider(rpc)
  await until("local Anvil", () => provider.getBlockNumber().then(() => true))
  const owner = new Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", provider)
  const artifact = path => JSON.parse(readFileSync(join(repo, "node_modules/@safe-global/safe-contracts/build/artifacts/contracts", path), "utf8"))
  const safeArtifact = artifact("Safe.sol/Safe.json")
  const singletonAddress = "0x41675C099F32341bf84BFc5382aF534df5C7461a"
  await provider.send("anvil_setCode", [singletonAddress, safeArtifact.deployedBytecode])
  assert.equal(utils.keccak256(await provider.getCode(singletonAddress)), "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4")
  const factoryArtifact = artifact("proxies/SafeProxyFactory.sol/SafeProxyFactory.json")
  const factory = await new ContractFactory(factoryArtifact.abi, factoryArtifact.bytecode, owner).deploy()
  await factory.deployed()
  const iface = new utils.Interface(safeArtifact.abi)
  const initializer = iface.encodeFunctionData("setup", [[owner.address], 1, zero, "0x", zero, zero, 0, zero])
  const receipt = await (await factory.createProxyWithNonce(singletonAddress, initializer, 1)).wait()
  const proxy = receipt.logs.map(log => { try { return factory.interface.parseLog(log) } catch { return null } }).find(log => log?.name === "ProxyCreation").args.proxy
  const safe = new Contract(proxy, safeArtifact.abi, owner)
  await (await owner.sendTransaction({ to: safe.address, value: 100 })).wait()
  note(`Official Safe 1.4.1 deployed on loopback Anvil: ${safe.address}`)

  let delegate
  let active = true
  let record
  let proposalSignature
  let tx
  const stats = { delegate_gets: 0, transaction_gets: 0, proposal_posts: 0, confirmation_posts: 0 }
  // There is intentionally no HTTP control endpoint. Test mutations happen
  // only through this process's lexical state, which the tunnel cannot reach.
  fixture = createServer(async (request, response) => {
    const answer = (status, value) => { response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); response.end(value === undefined ? "" : JSON.stringify(value)) }
    try {
      if (request.headers.authorization !== `Bearer ${apiKey}`) return answer(401, { detail: "fixture authentication required" })
      const url = new URL(request.url, "http://fixture.invalid")
      if (request.method === "GET" && url.pathname === "/api/v2/delegates/") {
        stats.delegate_gets++
        assert.equal(url.searchParams.get("delegate")?.toLowerCase(), delegate?.toLowerCase())
        return answer(200, { count: active ? 1 : 0, results: active ? [{ safe: safe.address, delegate, delegator: owner.address, label: "disposable integration proposer", expiryDate: null }] : [], next: null, previous: null })
      }
      if (url.pathname.endsWith("/confirmations/")) { stats.confirmation_posts++; return answer(400, { detail: "delegate must never confirm" }) }
      if (request.method === "GET" && /^\/api\/v1\/multisig-transactions\/0x[0-9a-f]{64}\/$/.test(url.pathname)) {
        stats.transaction_gets++
        return record && url.pathname.includes(record.safeTxHash) ? answer(200, record) : answer(404, { detail: "not found" })
      }
      if (request.method === "POST" && url.pathname === `/api/v1/safes/${safe.address}/multisig-transactions/`) {
        const chunks = []
        for await (const chunk of request) { chunks.push(chunk); assert(Buffer.concat(chunks).length < 16384) }
        const body = JSON.parse(Buffer.concat(chunks))
        assert(active, "revoked delegate")
        assert.equal(body.sender.toLowerCase(), delegate.toLowerCase())
        assert(!(await safe.getOwners()).some(address => address.toLowerCase() === delegate.toLowerCase()))
        tx = Object.fromEntries(types.SafeTx.map(({ name }) => [name, body[name]]))
        assert.equal(tx.to.toLowerCase(), recipient.toLowerCase())
        assert.equal(tx.value, "7")
        assert.equal(tx.operation, 0)
        const recomputed = utils._TypedDataEncoder.hash({ chainId: 31337, verifyingContract: safe.address }, types, tx)
        assert.equal(recomputed, await safe.getTransactionHash(...Object.values(tx)))
        assert.equal(recomputed, body.contractTransactionHash)
        assert.equal(utils.recoverAddress(recomputed, body.signature).toLowerCase(), delegate.toLowerCase())
        proposalSignature = body.signature
        stats.proposal_posts++
        record = { safe: safe.address, ...tx, safeTxHash: recomputed, confirmations: [], isExecuted: false }
        // The service stored the proposal, then the response was lost. This
        // forces a route retry to GET and validate the existing exact record.
        return answer(503, { detail: "fixture stored proposal; initial response intentionally lost" })
      }
      answer(404, { detail: "fixture route not found" })
    } catch (error) { answer(400, { detail: error.message }) }
  })
  await new Promise(resolve => fixture.listen(0, "127.0.0.1", resolve))
  const fixturePort = fixture.address().port
  await writeFile(join(work, "cloudflared.yml"), "{}\n", { mode: 0o600 })
  const tunnel = start(process.env.CLOUDFLARED_BIN || "cloudflared", ["tunnel", "--config", join(work, "cloudflared.yml"), "--no-autoupdate", "--protocol", "http2", "--url", `http://127.0.0.1:${fixturePort}`], "tunnel")
  const origin = await until("temporary trusted HTTPS fixture origin", async () => {
    if (tunnel.exitCode !== null) throw new Error("cloudflared exited")
    return (await readFile(join(logs, "tunnel.log"), "utf8")).match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/)?.[0]
  })
  const hostname = new URL(origin).hostname
  // Some macOS/VPN resolvers cache NXDOMAIN for newly issued tunnel names.
  // Resolve through c-ares only when getaddrinfo fails. Machine still performs
  // normal end-to-end TLS verification against the original HTTPS hostname.
  let proxyEnv = {}
  try { await lookup(hostname) } catch {
    const [address] = await until("fresh tunnel DNS propagation", () => resolve4(hostname))
    tunnelProxy = createServer((_, response) => { response.writeHead(403); response.end() })
    tunnelProxy.on("connect", (request, socket, head) => {
      if (request.url !== `${hostname}:443`) return socket.destroy()
      const upstream = connect({ host: address, port: 443 }, () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n")
        if (head.length) upstream.write(head)
        socket.pipe(upstream); upstream.pipe(socket)
      })
      upstream.on("error", () => socket.destroy())
      socket.on("error", () => upstream.destroy())
      socket.on("close", () => upstream.destroy())
    })
    await new Promise(resolve => tunnelProxy.listen(0, "127.0.0.1", resolve))
    proxyEnv = { HTTPS_PROXY: `http://127.0.0.1:${tunnelProxy.address().port}`, NO_PROXY: "127.0.0.1,localhost,::1" }
    evidence.tunnel_dns_workaround = "Exact-host loopback CONNECT proxy with c-ares resolution; TLS unchanged"
    note("Using exact-host loopback proxy for fresh tunnel DNS; HTTPS verification remains enabled")
  }
  await until("HTTPS tunnel connection", () => new Promise(resolve => {
    const request = httpsGet(`${origin}/`, { lookup: (name, options, callback) => {
      resolve4(name).then(([address]) => callback(null, options.all ? [{ address, family: 4 }] : address, 4), callback)
    }, timeout: 5000 }, response => { response.resume(); resolve(response.statusCode === 401) })
    request.on("error", () => resolve(false))
    request.on("timeout", () => request.destroy())
  }))
  note("Authenticated service fixture available through temporary trusted HTTPS tunnel")

  const ceremonyPort = await freePort()
  const nfsPort = await freePort()
  const configFile = join(work, "machine-config.toml")
  await writeFile(configFile, `default_chain = "anvil"\nnfs_listen_addr = "127.0.0.1:${nfsPort}"\n[chains.anvil]\nname = "anvil"\nchain_id = 31337\nrpc_urls = ["${rpc}"]\nrpc_endpoints = []\ndisplay_name = "Anvil (local)"\nnative_symbol = "ETH"\nnative_decimals = 18\nlegacy_tx = false\nop_stack = false\n[petals.runtime.safe.endpoints]\ntransaction-service = "${origin}"\n`, { mode: 0o600 })
  const ready = join(work, "ready")
  const stack = start(launcher, ["--developer-root", developerRoot, "--machine-home", machineHome, "--machine-socket", join(work, "machine.sock"), "--log-dir", logs, "--ready-file", ready, "--ceremony-port", String(ceremonyPort)], "launcher", {
    ...proxyEnv,
    BLOOM_INTEGRATION_MACHINE_BIN: machine, BLOOM_INTEGRATION_BROKER_BIN: broker, BLOOM_INTEGRATION_SIGNER_BIN: signer,
    BLOOM_TRIAD_DEV_MACHINE_CONFIG: configFile, BLOOM_TRIAD_DEV_BUILD_PETALS: "0",
    // The existing launcher accepts a generic package at this integration
    // hook, enrolling its exact route provenance before starting Broker.
    BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE: repo,
  })
  await until("real local Triad readiness", async () => { assert.equal(stack.exitCode, null, "Triad exited; inspect launcher log"); return exists(ready) }, 300000)
  note("Machine, Broker and Signer ready with compiled Safe package installed")
  const catalog = JSON.parse(await readFile(join(developerRoot, "config/provenance-catalog.json"), "utf8"))
  const installedHash = launchField(await readFile(join(logs, `${basename(repo)}-install.log`), "utf8"), "hash")
  const subject = catalog.records.find(row => row.subject.kind === "petal" && row.subject.package_hash === installedHash && row.operation_classes.some(op => op.operation_class === "safe.transaction.confirm"))?.subject
  assert(subject?.package_hash, "Safe signing provenance missing")
  evidence.package_hash = subject.package_hash

  // Public standard test mnemonic; never use this fixture wallet outside Anvil.
  await writeFile(mnemonicFile, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n", { mode: 0o600 })
  const imported = await cli("wallet", "import", "safe-delegate-anvil")
  const wallet = (await complete(launchField(imported, "ceremony_url"), ["--mnemonic-file", mnemonicFile])).wallet_id
  assert(wallet)
  await unlink(mnemonicFile)
  await vwrite(`/wallets/${wallet}/new`, { request_id: "delegate-account-one" })
  const allocation = (await vjson(`/wallets/${wallet}/new`)).requests.find(request => request.request_id === "delegate-account-one")
  await complete(allocation.ceremony_url)
  await until("Signer allocated account 1", async () => (await vjson(`/wallets/${wallet}/new`)).requests.some(request => request.request_id === "delegate-account-one" && request.state === "created" && request.number === 1))
  delegate = (await vcat(`/wallets/${wallet}/1/address.evm`)).trim()
  assert.notEqual(delegate.toLowerCase(), (await vcat(`/wallets/${wallet}/0/address.evm`)).trim().toLowerCase())
  assert(!(await safe.getOwners()).map(address => address.toLowerCase()).includes(delegate.toLowerCase()))
  const policy = await vjson(`/wallets/${wallet}/policy.json`)
  policy.allowed_petal_packages = [...new Set([...policy.allowed_petal_packages, subject.package_hash])].sort()
  policy.allowed_destinations = [...policy.allowed_destinations, { chain: "evm-31337", destination: "exact" }]
  const policyFile = join(work, "policy.json")
  await writeFile(policyFile, JSON.stringify(policy), { mode: 0o600 })
  const policyLaunch = await cli("wallet", "update-policy", wallet, "--file", policyFile)
  await complete(launchField(policyLaunch, "ceremony_url"))
  await cli("wallet", "commit-policy", launchField(policyLaunch, "operation_id"))
  note(`Disposable Bloom account 1 allocated and signing policy approved: ${delegate}`)

  const safePath = `/petals/safe/safes/${wallet}/1/treasury.json`
  const binding = { chain: "anvil", safe_address: safe.address, mode: "delegate", transaction_service: origin }
  await vwrite(`/petals/safe/service-keys/${wallet}/1/treasury`, apiKey)
  await refused("default owner mode rejects non-owner account", () => vwrite(safePath, { ...binding, mode: "owner" }), /not a current Safe owner/)
  await vwrite(safePath, binding)
  assert.equal((await vjson(safePath)).binding.mode, "delegate")
  const path = `/petals/safe/transactions/${wallet}/1/proposal`
  await vwrite(`${path}/draft.json`, { safe_id: "treasury", transaction: { kind: "native_transfer", to: recipient, value: "7" } })
  assert.match(await vcat(`${path}/plan.md`), /delegate-only proposer/)
  await refused("delegate confirm is refused", () => vwrite(`${path}/confirm.json`), /delegate-only/)
  await refused("delegate execute is refused", () => vwrite(`${path}/execute.json`, { signatures: [] }), /delegate-only/)
  await vwrite(`${path}/propose.json`)
  const pending = await vjson(`${path}/status.json`)
  assert.equal(pending.phase, "approval_required")
  assert.equal(pending.mode, "delegate")
  assert.equal(stats.proposal_posts, 0, "service publication happened before approval")
  const approval = await vjson(`/petal-signing-requests/${pending.approval_action_id}.json`)
  assert.equal(approval.operation_class, "safe.transaction.confirm")
  const ceremonyURL = new URL(approval.ceremony_url)
  const token = ceremonyURL.hash.startsWith("#cap=") ? ceremonyURL.hash.slice(5) : ceremonyURL.pathname.split("/").at(-1)
  const response = await fetch(`${ceremonyURL.origin}/api/session`, { headers: { "X-Bloom-Ceremony-Token": token } })
  assert.equal(response.status, 200)
  const session = await response.json()
  const review = session.review_manifest.safe_review || JSON.parse(session.review_manifest.canonical_plan).safe_review
  assert(review, "Broker independently rebuilt no Safe review")
  assert.equal(review.owner.toLowerCase(), delegate.toLowerCase())
  assert.equal(review.safe.toLowerCase(), safe.address.toLowerCase())
  assert.equal(review.safe_tx_hash, pending.safe_tx_hash)
  assert.equal(review.value, "7")
  assert.equal(review.destination.toLowerCase(), recipient.toLowerCase())
  evidence.checks.push("Broker independently reviewed exact Safe hash, account 1 signer, recipient and value before approval")
  await complete(approval.ceremony_url)
  await refused("first service response is lost after verified proposal storage", () => vwrite(`${path}/propose.json`), /initial response intentionally lost/)
  assert.equal((await vjson(`${path}/status.json`)).phase, "proposal_signed")
  assert.equal(stats.proposal_posts, 1)
  assert(proposalSignature)
  await vwrite(`${path}/propose.json`)
  const proposed = await vjson(`${path}/status.json`)
  assert.equal(proposed.phase, "proposed")
  assert.equal(proposed.service_status, "proposed")
  await vwrite(`${path}/propose.json`)
  assert.equal(stats.proposal_posts, 1)
  assert.equal(stats.confirmation_posts, 0)
  assert.equal(record.confirmations.length, 0)
  const publicText = JSON.stringify(proposed) + await vcat(`${path}/plan.md`) + await vcat(safePath)
  assert(!publicText.includes(proposalSignature))
  assert(!publicText.includes(apiKey))
  assert.match(await vcat(`${path}/plan.md`), /Signatures Bloom holds: 0/)
  evidence.checks.push("Cryptographically verified delegate signature, zero owner confirmations, lost-response exact retry and idempotent replay", "Route reads expose neither held signature nor service credential")
  note("Compiled delegate flow passed Broker ceremony, signed with account 1, and recovered stored proposal on exact retry")

  const revokedPath = `/petals/safe/transactions/${wallet}/1/revoked`
  await vwrite(`${revokedPath}/draft.json`, { safe_id: "treasury", transaction: { kind: "rejection" } })
  active = false
  await refused("revoked delegate cannot propose an existing draft", () => vwrite(`${revokedPath}/propose.json`), /no current owner delegation/)
  await refused("revoked delegate cannot bind", () => vwrite(safePath, binding), /no current owner delegation/)
  await refused("revoked delegate cannot draft", () => vwrite(`/petals/safe/transactions/${wallet}/1/no-grant/draft.json`, { safe_id: "treasury", transaction: { kind: "rejection" } }), /no current owner delegation/)
  active = true
  const args = Object.values(tx)
  await assert.rejects(safe.callStatic.execTransaction(...args.slice(0, 9), proposalSignature), /GS026|revert|CALL_EXCEPTION/)
  assert.equal((await safe.nonce()).toString(), "0")
  const before = await provider.getBalance(recipient)
  const ownerSignature = utils.joinSignature(owner._signingKey().signDigest(record.safeTxHash))
  const executed = await (await safe.execTransaction(...args.slice(0, 9), ownerSignature)).wait()
  assert.equal(executed.status, 1)
  assert.equal((await provider.getBalance(recipient)).sub(before).toString(), "7")
  assert.equal((await safe.nonce()).toString(), "1")
  const consumed = await vjson(`${path}/status.json`)
  assert.equal(consumed.phase, "nonce_conflict")
  assert.equal(consumed.current_safe_nonce, "1")
  evidence.checks.push("Delegate signature alone is rejected by real Safe contract", "Actual Safe owner executes exactly proposed transaction and status observes consumed nonce")
  evidence.safe = safe.address
  evidence.delegate = delegate
  evidence.wallet_index = 1
  evidence.safe_tx_hash = record.safeTxHash
  evidence.owner_execution_tx_hash = executed.transactionHash
  evidence.service_requests = stats
  evidence.result = "passed"
  note("Revocation barriers and on-chain separation passed: delegate refused, owner executed exact proposal")
} catch (error) {
  evidence.result = "failed"
  // Child-process errors include arguments. Keep fixture secrets and ceremony
  // capabilities out of the result and terminal diagnostics.
  const redact = value => String(value).replaceAll(apiKey, "[fixture key]").replace(/0x[0-9a-fA-F]{66,}/g, "[redacted hex]").replace(/(\/ceremony\/(?:#cap=)?)[a-zA-Z0-9_-]+/g, "$1[capability]")
  evidence.error = redact(error.stderr || (typeof error.actual === "string" ? `${error.message}: ${error.actual}` : error.message))
  console.error(`[delegate triad] FAILED: ${evidence.error}`)
  process.exitCode = 1
} finally {
  if (provider) {
    provider.removeAllListeners()
    provider.polling = false
  }
  await unlink(mnemonicFile).catch(() => {})
  for (const child of children.reverse()) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM")
      await Promise.race([new Promise(resolve => child.once("exit", resolve)), sleep(15000)])
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL")
    }
  }
  if (fixture) { fixture.closeAllConnections(); await new Promise(resolve => fixture.close(resolve)) }
  if (tunnelProxy) await new Promise(resolve => tunnelProxy.close(resolve))
  await writeFile(join(work, "evidence.json"), JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600 })
  console.log(`[delegate triad] ${evidence.result}; evidence retained at ${join(work, "evidence.json")}`)
}
