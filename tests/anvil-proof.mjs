import { readFileSync } from "node:fs"
import ethersPackage from "ethers"

const { Contract, ContractFactory, Wallet, providers, utils } = ethersPackage
const artifact = (path) => JSON.parse(readFileSync(`node_modules/@safe-global/safe-contracts/build/artifacts/contracts/${path}`, "utf8"))
const provider = new providers.JsonRpcProvider(process.env.ANVIL_RPC_URL || "http://127.0.0.1:18545")
const owner = new Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", provider)
const recipient = "0x4000000000000000000000000000000000000000"
let nonce = await provider.getTransactionCount(owner.address)

const deploy = async (path) => {
  const value = artifact(path)
  const contract = await new ContractFactory(value.abi, value.bytecode, owner).deploy({ nonce: nonce++ })
  await contract.deployed()
  return contract
}
const deployArtifact = async (value) => {
  const contract = await new ContractFactory(value.abi, value.bytecode.object, owner).deploy({ nonce: nonce++ })
  await contract.deployed()
  return contract
}

const safeArtifact = artifact("Safe.sol/Safe.json")
const createArtifact = artifact("libraries/CreateCall.sol/CreateCall.json")
const multiSendArtifact = artifact("libraries/MultiSendCallOnly.sol/MultiSendCallOnly.json")
const singletonAddress = "0x41675C099F32341bf84BFc5382aF534df5C7461a"
const createCallAddress = "0x9b35Af71d77eaf8d7e40252370304687390A1A52"
const multiSendAddress = "0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
await provider.send("anvil_setCode", [singletonAddress, safeArtifact.deployedBytecode])
await provider.send("anvil_setCode", [createCallAddress, createArtifact.deployedBytecode])
await provider.send("anvil_setCode", [multiSendAddress, multiSendArtifact.deployedBytecode])
if (utils.keccak256(await provider.getCode(singletonAddress)) !== "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4") throw new Error("official Safe runtime hash differs")
if (utils.keccak256(await provider.getCode(createCallAddress)) !== "0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889") throw new Error("official CreateCall runtime hash differs")
if (utils.keccak256(await provider.getCode(multiSendAddress)) !== "0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939") throw new Error("official MultiSendCallOnly runtime hash differs")
const singleton = new Contract(singletonAddress, safeArtifact.abi, owner)
const createCall = new Contract(createCallAddress, createArtifact.abi, owner)
const multiSend = new Contract(multiSendAddress, multiSendArtifact.abi, owner)
const factory = await deploy("proxies/SafeProxyFactory.sol/SafeProxyFactory.json")
const zero = "0x0000000000000000000000000000000000000000"
const initializer = singleton.interface.encodeFunctionData("setup", [[owner.address], 1, zero, "0x", zero, zero, 0, zero])
const receipt = await (await factory.createProxyWithNonce(singletonAddress, initializer, 1, { nonce: nonce++ })).wait()
const proxyLog = receipt.logs.map((log) => { try { return factory.interface.parseLog(log) } catch { return null } }).find(Boolean)
const safe = new Contract(proxyLog.args.proxy, singleton.interface, owner)
await (await owner.sendTransaction({ to: safe.address, value: utils.parseEther("2"), nonce: nonce++ })).wait()

const types = { SafeTx: [
  {name:"to",type:"address"},{name:"value",type:"uint256"},{name:"data",type:"bytes"},{name:"operation",type:"uint8"},
  {name:"safeTxGas",type:"uint256"},{name:"baseGas",type:"uint256"},{name:"gasPrice",type:"uint256"},{name:"gasToken",type:"address"},
  {name:"refundReceiver",type:"address"},{name:"nonce",type:"uint256"}
] }
const makeTx = (to, value, data, operation, safeNonce) => ({to,value,data,operation,safeTxGas:0,baseGas:0,gasPrice:0,gasToken:zero,refundReceiver:zero,nonce:safeNonce})
const execute = async (safeContract, safeTx, signers = [owner]) => {
  const args = Object.values(safeTx)
  const hash = await safeContract.getTransactionHash(...args)
  const typedHash = utils._TypedDataEncoder.hash({chainId:31337,verifyingContract:safeContract.address}, types, safeTx)
  if (hash !== typedHash) throw new Error("Safe contract and EIP-712 hash differ")
  const signature = utils.hexConcat(signers
    .map((signer) => [signer.address.toLowerCase(), utils.joinSignature(signer._signingKey().signDigest(hash))])
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, signature]) => signature))
  const execution = await safeContract.execTransaction(...args.slice(0, 9), signature, { nonce: nonce++ })
  const executionReceipt = await execution.wait()
  if (executionReceipt.status !== 1) throw new Error("Safe execution reverted")
  return hash
}

const balance = async (address) => BigInt(await provider.send("eth_getBalance", [address, "latest"]))
const before = await balance(recipient)
const transferHash = await execute(safe, makeTx(recipient, utils.parseEther("1"), "0x", 0, 0))
if ((await balance(recipient)) - before !== BigInt(utils.parseEther("1").toString())) throw new Error("native transfer failed")

const tokenArtifact = JSON.parse(readFileSync("target/forge/FixtureToken.sol/FixtureToken.json", "utf8"))
const token = await deployArtifact(tokenArtifact)
await (await token.transfer(safe.address, 100, { nonce: nonce++ })).wait()
const tokenRecipient = "0x6000000000000000000000000000000000000000"
const tokenData = token.interface.encodeFunctionData("transfer", [tokenRecipient, 7])
const erc20Hash = await execute(safe, makeTx(token.address, 0, tokenData, 0, 1))
if (!(await token.balanceOf(tokenRecipient)).eq(7)) throw new Error("ERC-20 transfer failed")

const initcode = "0x6001600c60003960016000f300"
const salt = utils.hexZeroPad("0x01", 32)
const createData = createCall.interface.encodeFunctionData("performCreate2", [0, initcode, salt])
const predicted = utils.getCreate2Address(safe.address, salt, utils.keccak256(initcode))
const create2Hash = await execute(safe, makeTx(createCall.address, 0, createData, 1, 2))
if ((await provider.getCode(predicted)) === "0x") throw new Error("CREATE2 through Safe delegatecall failed")

const createNonce = await provider.getTransactionCount(safe.address)
const created = utils.getContractAddress({from:safe.address,nonce:createNonce})
const createDataRegular = createCall.interface.encodeFunctionData("performCreate", [0, initcode])
const createHash = await execute(safe, makeTx(createCall.address, 0, createDataRegular, 1, 3))
if ((await provider.getCode(created)) === "0x") throw new Error("CREATE through Safe delegatecall failed")

const secondRecipient = "0x5000000000000000000000000000000000000000"
const packedCall = utils.solidityPack(["uint8","address","uint256","uint256","bytes"], [0,secondRecipient,2,0,"0x"])
const multiSendData = multiSend.interface.encodeFunctionData("multiSend", [packedCall])
const batchHash = await execute(safe, makeTx(multiSend.address, 0, multiSendData, 1, 4))
if ((await balance(secondRecipient)) !== 2n) throw new Error("call-only batch transfer failed")
const rejectionHash = await execute(safe, makeTx(safe.address, 0, "0x", 0, 5))
if (!(await safe.nonce()).eq(6)) throw new Error("Safe nonce did not advance")

const secondOwner = new Wallet("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", provider)
const thresholdInitializer = singleton.interface.encodeFunctionData("setup", [[[owner.address, secondOwner.address].sort()], 2, zero, "0x", zero, zero, 0, zero].flat())
const thresholdReceipt = await (await factory.createProxyWithNonce(singletonAddress, thresholdInitializer, 2, { nonce: nonce++ })).wait()
const thresholdLog = thresholdReceipt.logs.map((log) => { try { return factory.interface.parseLog(log) } catch { return null } }).find(Boolean)
const thresholdSafe = new Contract(thresholdLog.args.proxy, singleton.interface, owner)
await (await owner.sendTransaction({ to: thresholdSafe.address, value: 10, nonce: nonce++ })).wait()
const thresholdHash = await execute(thresholdSafe, makeTx(recipient, 3, "0x", 0, 0), [owner, secondOwner])
if (!(await thresholdSafe.nonce()).eq(1)) throw new Error("threshold Safe execution failed")

console.log(JSON.stringify({safe:safe.address,singleton:singletonAddress,owner:owner.address,transferHash,erc20Hash,createHash,create2Hash,batchHash,rejectionHash,thresholdHash,predicted,created,nonce:(await safe.nonce()).toString()}))
