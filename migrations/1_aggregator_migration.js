const FullAggregator = artifacts.require("FullAggregator");
const LightAggregator = artifacts.require("LightAggregator");
const LightVerifier = artifacts.require("LightVerifier");
const { getLinkAddress } = require("./utils");

module.exports = async function(deployer, network, accounts) {
  if (network == "test") return;
  const link = getLinkAddress(deployer, network, accounts);
  const debridgeInitParams = require("../assets/debridgeInitParams")[network];
  let aggregatorInstance;
  if (debridgeInitParams.type == "full") {
    await deployer.deploy(
      FullAggregator,
      debridgeInitParams.oracleCount,
      debridgeInitParams.oraclePayment,
      link
    );
    await deployer.deploy(
      LightAggregator,
      debridgeInitParams.oracleCount,
      debridgeInitParams.oraclePayment,
      link
    );
    aggregatorInstance = await FullAggregator.deployed();
    let lightAggregatorInstance = await LightAggregator.deployed();
    for (let oracle of debridgeInitParams.oracles) {
      await aggregatorInstance.addOracle(oracle.address, oracle.admin);
      await lightAggregatorInstance.addOracle(oracle.address, oracle.admin);
    }
  } else {
    await deployer.deploy(LightVerifier, debridgeInitParams.oracleCount);
    aggregatorInstance = await LightVerifier.deployed();
    for (let oracle of debridgeInitParams.oracles) {
      await aggregatorInstance.addOracle(oracle.address);
    }
  }
};
