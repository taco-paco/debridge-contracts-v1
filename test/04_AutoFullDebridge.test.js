const { expectRevert } = require("@openzeppelin/test-helpers");
const { ZERO_ADDRESS, permit } = require("./utils.spec");
const FullAggregator = artifacts.require("FullAggregator");
const MockLinkToken = artifacts.require("MockLinkToken");
const MockToken = artifacts.require("MockToken");
const Debridge = artifacts.require("FullDebridge");
const WrappedAsset = artifacts.require("WrappedAsset");
const FeeProxy = artifacts.require("FeeProxy");
const CallProxy = artifacts.require("CallProxy");
const UniswapV2Factory = artifacts.require("UniswapV2Factory");
const IUniswapV2Pair = artifacts.require("IUniswapV2Pair");
const DefiController = artifacts.require("DefiController");
const { deployProxy } = require("@openzeppelin/truffle-upgrades");
const { MAX_UINT256 } = require("@openzeppelin/test-helpers/src/constants");
const WETH9 = artifacts.require("WETH9");
const { toWei, fromWei, toBN } = web3.utils;
const MAX = web3.utils.toTwosComplement(-1);
const bobPrivKey =
  "0x79b2a2a43a1e9f325920f99a720605c9c563c61fb5ae3ebe483f83f1230512d3";

contract("FullDebridge", function ([alice, bob, carol, eve, devid]) {
    const reserveAddress = devid;
    before(async function() {
      this.mockToken = await MockToken.new("Link Token", "dLINK", 18, {
        from: alice,
      });
      this.linkToken = await MockLinkToken.new("Link Token", "dLINK", 18, {
        from: alice,
      });
      this.dbrToken = await MockLinkToken.new("DBR", "DBR", 18, {
        from: alice,
      });
      this.amountThreshols = toWei("1000");
      this.oraclePayment = toWei("0.001");
      this.bonusPayment = toWei("0.001");
      this.minConfirmations = 1;
      this.confirmationThreshold = 5; //Confirmations per block before extra check enabled.
      this.excessConfirmations = 3; //Confirmations count in case of excess activity.
  
      this.aggregator = await FullAggregator.new(
        this.minConfirmations,
        this.oraclePayment,
        this.bonusPayment,
        this.linkToken.address,
        this.dbrToken.address,
        this.confirmationThreshold,
        this.excessConfirmations,
        alice,
        ZERO_ADDRESS,
        {
          from: alice,
        }
      );
      this.initialOracles = [
        {
          address: alice,
          admin: alice,
        },
        {
          address: bob,
          admin: carol,
        },
        {
          address: eve,
          admin: carol,
        },
        devid
      ];
      for (let oracle of this.initialOracles) {
        await this.aggregator.addOracle(oracle.address, oracle.admin, {
          from: alice,
        });
      }
      this.uniswapFactory = await UniswapV2Factory.new(carol, {
        from: alice,
      });
      this.feeProxy = await FeeProxy.new(
        this.linkToken.address,
        this.uniswapFactory.address,
        {
          from: alice,
        }
      );
      this.callProxy = await CallProxy.new({
        from: alice,
      });
      this.defiController = await DefiController.new({
        from: alice,
      });
      const maxAmount = toWei("1000000");
      const fixedNativeFee = toWei("0.00001");
      const transferFee = toWei("0.001");
      const minReserves = toWei("0.2");
      const isSupported = true;
      const supportedChainIds = [42, 56];
      this.weth = await WETH9.new({
        from: alice,
      });
  
      //     uint256 _excessConfirmations,
      //     address _ligthAggregator,
      //     address _fullAggregator,
      //     address _callProxy,
      //     uint256[] memory _supportedChainIds,
      //     ChainSupportInfo[] memory _chainSupportInfo,
      //     IWETH _weth,
      //     IFeeProxy _feeProxy,
      //     IDefiController _defiController
      this.debridge = await deployProxy(Debridge, [
        this.excessConfirmations,
        ZERO_ADDRESS,
        ZERO_ADDRESS,
        this.callProxy.address.toString(),
        supportedChainIds,
        [
          {
            transferFee,
            fixedNativeFee,
            isSupported,
          },
          {
            transferFee,
            fixedNativeFee,
            isSupported,
          },
        ],
        ZERO_ADDRESS,
        ZERO_ADDRESS,
        ZERO_ADDRESS,
      ]);
      await this.aggregator.setDebridgeAddress(this.debridge.address.toString());
    });
  
    context("Test setting configurations by different users", () => {
      it("should set aggregator if called by the admin", async function() {
        const aggregator = this.aggregator.address;
        await this.debridge.setAggregator(aggregator, false, {
          from: alice,
        });
        const newAggregator = await this.debridge.fullAggregator();
        assert.equal(aggregator, newAggregator);
      });
  
      it("should set fee proxy if called by the admin", async function() {
        const feeProxy = this.feeProxy.address;
        await this.debridge.setFeeProxy(feeProxy, {
          from: alice,
        });
        const newFeeProxy = await this.debridge.feeProxy();
        assert.equal(feeProxy, newFeeProxy);
      });
  
      it("should set defi controller if called by the admin", async function() {
        const defiController = this.defiController.address;
        await this.debridge.setDefiController(defiController, {
          from: alice,
        });
        const newDefiController = await this.debridge.defiController();
        assert.equal(defiController, newDefiController);
      });
  
      it("should set weth if called by the admin", async function() {
        const weth = this.weth.address;
        await this.debridge.setWeth(weth, {
          from: alice,
        });
        const newWeth = await this.debridge.weth();
        assert.equal(weth, newWeth);
      });
  
      it("should reject setting aggregator if called by the non-admin", async function() {
        await expectRevert(
          this.debridge.setAggregator(ZERO_ADDRESS, false, {
            from: bob,
          }),
          "onlyAdmin: bad role"
        );
      });
  
      it("should reject setting fee proxy if called by the non-admin", async function() {
        await expectRevert(
          this.debridge.setFeeProxy(ZERO_ADDRESS, {
            from: bob,
          }),
          "onlyAdmin: bad role"
        );
      });
  
      it("should reject setting defi controller if called by the non-admin", async function() {
        await expectRevert(
          this.debridge.setDefiController(ZERO_ADDRESS, {
            from: bob,
          }),
          "onlyAdmin: bad role"
        );
      });
  
      it("should reject setting weth if called by the non-admin", async function() {
        await expectRevert(
          this.debridge.setWeth(ZERO_ADDRESS, {
            from: bob,
          }),
          "onlyAdmin: bad role"
        );
      });
    });
  
    context("Test managing assets", () => {
      before(async function() {
        currentChainId = await this.debridge.chainId();
        const newSupply = toWei("100");
        await this.linkToken.mint(alice, newSupply, {
          from: alice,
        });
        await this.dbrToken.mint(alice, newSupply, {
          from: alice,
        });
        await this.dbrToken.transferAndCall(
          this.aggregator.address.toString(),
          newSupply,
          "0x",
          {
            from: alice,
          }
        );
        await this.linkToken.transferAndCall(
          this.aggregator.address.toString(),
          newSupply,
          "0x",
          {
            from: alice,
          }
        );
      });
  
      const isSupported = true;
      it("should add external asset if called by the admin", async function() {
        const tokenAddress = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
        const chainId = 56;
        const maxAmount = toWei("100000000000000000");
        const amountThreshold = toWei("10000000000000");
        const fixedNativeFee = toWei("0.00001");
        const transferFee = toWei("0.01");
        const minReserves = toWei("0.2");
        const supportedChainIds = [42, 3, 56];
        const name = "MUSD";
        const symbol = "Magic Dollar";
        const decimals = 18;
        const debridgeId = await this.debridge.getDebridgeId(
          chainId,
          tokenAddress
        );
          //   function confirmNewAsset(
          //     address _tokenAddress,
          //     uint256 _chainId,
          //     string memory _name,
          //     string memory _symbol,
          //     uint8 _decimals
          // )
        await this.aggregator.confirmNewAsset(tokenAddress, chainId, name, symbol, decimals, {
          from: this.initialOracles[0].address,
        });
  
          //   function getDeployId(
          //     bytes32 _debridgeId,
          //     string memory _name,
          //     string memory _symbol,
          //     uint8 _decimals
          // )
        // let deployId = await this.aggregator.getDeployId(debridgeId, name, symbol, decimals) 
        // //function deployAsset(bytes32 _deployId)
        // await this.debridge.checkAndDeployAsset(debridgeId, {
        //   from: this.initialOracles[0].address,
        // });
        await this.debridge.updateAsset(
          debridgeId,
          maxAmount,
          minReserves,
          amountThreshold,
          {
            from: alice,
          }
        );
        const debridge = await this.debridge.getDebridge(debridgeId);
        assert.equal(debridge.maxAmount.toString(), maxAmount);
        assert.equal(debridge.collectedFees.toString(), "0");
        assert.equal(debridge.balance.toString(), "0");
        assert.equal(debridge.minReserves.toString(), minReserves);
      });
    });

  context("Test send method", () => {
    it("should send native tokens from the current chain", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const chainId = await this.debridge.chainId();
      const receiver = bob;
      const amount = toBN(toWei("1"));
      const chainIdTo = 42;
      const claimFee = toBN(toWei("0.0001"));
      const data = "0x";
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const balance = toBN(await web3.eth.getBalance(this.debridge.address));
      const debridge = await this.debridge.getDebridge(debridgeId);
      const supportedChainInfo = await this.debridge.getChainSupport(chainIdTo);

      const fees = toBN(supportedChainInfo.transferFee)
        .mul(amount)
        .div(toBN(toWei("1")));
        //.add(toBN(supportedChainInfo.fixedFee));
      const collectedNativeFees = await this.debridge.collectedFees();
      await this.debridge.autoSend(
        tokenAddress,
        receiver,
        amount,
        chainIdTo,
        reserveAddress,
        claimFee,
        data,
        false,
        {
          value: amount,
          from: alice,
        }
      );
      const newBalance = toBN(await web3.eth.getBalance(this.debridge.address));
      const newCollectedNativeFees = await this.debridge.collectedFees();
      const newDebridge = await this.debridge.getDebridge(debridgeId);
      assert.equal(balance.add(amount).toString(), newBalance.toString());
      assert.equal(
        debridge.collectedFees

          .add(toBN(supportedChainInfo.fixedNativeFee))
          .add(fees)
          .toString(),
        newDebridge.collectedFees.toString()
      );
      assert.equal(
        collectedNativeFees.toString(),
        newCollectedNativeFees.toString()
      );
    });

  //   it("should update asset if called by the admin after deploy assets by send", async function () {
  //     const tokenAddress = ZERO_ADDRESS;
  //     const chainId = await this.debridge.chainId();
  //     const debridgeId = await this.debridge.getDebridgeId(
  //       chainId,
  //       tokenAddress
  //     );
  //     const maxAmount = toWei("100000000000");
  //     const amountThreshold = toWei("10000000000000");
  //     const minReserves = toWei("0.2");

  //     await this.debridge.updateAsset(
  //       debridgeId,
  //       maxAmount,
  //       minReserves,
  //       amountThreshold,
  //       {
  //         from: alice,
  //       }
  //     );
  //     const debridge = await this.debridge.getDebridge(debridgeId);
  //     assert.equal(debridge.maxAmount.toString(), maxAmount);
  //     assert.equal(debridge.collectedFees.toString(), "0");
  //     assert.equal(debridge.balance.toString(), "0");
  //     assert.equal(debridge.minReserves.toString(), minReserves);
  // });

    it("should send ERC20 tokens from the current chain", async function() {
      const tokenAddress = this.mockToken.address;
      const chainId = await this.debridge.chainId();
      const receiver = bob;
      const amount = toBN(toWei("100"));
      const chainIdTo = 42;
      const claimFee = toBN(toWei("0.0001"));
      const data = "0x";
      await this.mockToken.mint(alice, amount, {
        from: alice,
      });
      await this.mockToken.approve(this.debridge.address, amount, {
        from: alice,
      });
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const balance = toBN(
        await this.mockToken.balanceOf(this.debridge.address)
      );
      const debridge = await this.debridge.getDebridge(debridgeId);
      const supportedChainInfo = await this.debridge.getChainSupport(chainIdTo);
      const collectedNativeFees = await this.debridge.collectedFees();
      const fees = toBN(supportedChainInfo.transferFee)
        .mul(amount)
        .div(toBN(toWei("1")));
        //.add(toBN(supportedChainInfo.fixedFee));
      await this.debridge.autoSend(
        tokenAddress,
        receiver,
        amount,
        chainIdTo,
        reserveAddress,
        claimFee,
        data,
        false,
        {
          value: supportedChainInfo.fixedNativeFee,
          from: alice,
        }
      );
      const newCollectedNativeFees = await this.debridge.collectedFees();
      const newBalance = toBN(
        await this.mockToken.balanceOf(this.debridge.address)
      );
      const newDebridge = await this.debridge.getDebridge(debridgeId);
      assert.equal(balance.add(amount).toString(), newBalance.toString());
      assert.equal(
        debridge.collectedFees.add(fees).toString(),
        newDebridge.collectedFees.toString()
      );
      assert.equal(
        collectedNativeFees
          .add(toBN(supportedChainInfo.fixedNativeFee))
          .toString(),
        newCollectedNativeFees.toString()
      );
    });

    it("should reject sending too mismatched amount of native tokens", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const receiver = bob;
      const chainId = await this.debridge.chainId();
      const amount = toBN(toWei("1"));
      const claimFee = toBN(toWei("0.0001"));
      const data = "0x";
      const chainIdTo = 42;
      // const debridgeId = await this.debridge.getDebridgeId(
      //   chainId,
      //   tokenAddress
      // );
      await expectRevert(
        this.debridge.autoSend(
          tokenAddress,
          receiver,
          amount,
          chainIdTo,
          reserveAddress,
          claimFee,
          data,
          false,
          {
            value: toWei("0.1"),
            from: alice,
          }
        ),
        "send: amount mismatch"
      );
    });

    it("should reject sending with no claim fee", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const receiver = bob;
      const chainId = await this.debridge.chainId();
      const amount = toBN(toWei("1"));
      const claimFee = toBN(toWei("0"));
      const data = "0x";
      const chainIdTo = 42;
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      await expectRevert(
        this.debridge.autoSend(
          tokenAddress,
          receiver,
          amount,
          chainIdTo,
          reserveAddress,
          claimFee,
          data,
          false,
          {
            value: amount,
            from: alice,
          }
        ),
        "autoSend: fee too low"
      );
    });

    it("should reject sending with too high fee", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const receiver = bob;
      const chainId = await this.debridge.chainId();
      const amount = toBN(toWei("1"));
      const claimFee = toBN(toWei("10"));
      const data = "0x";
      const chainIdTo = 56;
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      await expectRevert(
        this.debridge.autoSend(
          tokenAddress,
          receiver,
          amount,
          chainIdTo,
          reserveAddress,
          claimFee,
          data,
          false,
          {
            value: amount,
            from: alice,
          }
        ),
        "autoSend: proposed fee too high"
      );
    });

    it("should reject sending tokens to unsupported chain", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const receiver = bob;
      const chainId = await this.debridge.chainId();
      const amount = toBN(toWei("1"));
      const claimFee = toBN(toWei("0.0001"));
      const data = "0x";
      const chainIdTo = chainId;
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      await expectRevert(
        this.debridge.autoSend(
          tokenAddress,
          receiver,
          amount,
          chainIdTo,
          reserveAddress,
          claimFee,
          data,
          false,
          {
            value: amount,
            from: alice,
          }
        ),
        "send: wrong targed chain"
      );
    });

    it("should reject sending tokens originated on the other chain", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const receiver = bob;
      const amount = toBN(toWei("1"));
      const claimFee = toBN(toWei("0.0001"));
      const data = "0x";
      const chainIdTo = 42;
      const debridgeId = await this.debridge.getDebridgeId(42, tokenAddress);
      await expectRevert(
        this.debridge.autoSend(
          tokenAddress,
          receiver,
          amount,
          chainIdTo,
          reserveAddress,
          claimFee,
          data,
          false,
          {
            value: amount,
            from: alice,
          }
        ),
        "send: not native chain"
      );
    });
  });

  context("Test mint method", () => {
    const tokenAddress = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
    const chainId = 56;
    const receiver = bob;
    const amount = toBN(toWei("100"));
    const claimFee = toBN(toWei("1"));
    const data = "0x";
    const nonce = 2;
    let currentChainId;
    before(async function() {
      currentChainId = await this.debridge.chainId();
      const newSupply = toWei("100");
      await this.dbrToken.mint(alice, newSupply, {
        from: alice,
      });
      await this.linkToken.mint(alice, newSupply, {
        from: alice,
      });
      await this.dbrToken.transferAndCall(
        this.aggregator.address.toString(),
        newSupply,
        "0x",
        {
          from: alice,
        }
      );
      await this.linkToken.transferAndCall(
        this.aggregator.address.toString(),
        newSupply,
        "0x",
        {
          from: alice,
        }
      );
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const submission = await this.debridge.getAutoSubmisionId(
        debridgeId,
        chainId,
        currentChainId,
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      await this.aggregator.submit(submission, {
        from: bob,
      });
    });

    it("should mint when the submission is approved", async function() {
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const debridge = await this.debridge.getDebridge(debridgeId);
      const wrappedAsset = await WrappedAsset.at(debridge.tokenAddress);
      const workerBalance = toBN(await wrappedAsset.balanceOf(alice));
      const balance = toBN(await wrappedAsset.balanceOf(receiver));
      await this.debridge.autoMint(
        debridgeId,
        chainId,
        receiver,
        amount,
        nonce,
        reserveAddress,
        claimFee,
        data,
        [],
        {
          from: alice,
        }
      );
      const newBalance = toBN(await wrappedAsset.balanceOf(receiver));
      const newWorkerBalance = toBN(await wrappedAsset.balanceOf(alice));
      const submissionId = await this.debridge.getAutoSubmisionId(
        debridgeId,
        chainId,
        currentChainId,
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      const isSubmissionUsed = await this.debridge.isSubmissionUsed(
        submissionId
      );
      assert.equal(balance.add(amount).toString(), newBalance.toString());
      assert.equal(
        workerBalance.add(claimFee).toString(),
        newWorkerBalance.toString()
      );
      assert.ok(isSubmissionUsed);
    });

    it("should reject minting with unconfirmed submission", async function() {
      const nonce = 4;
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      await expectRevert(
        this.debridge.autoMint(
          debridgeId,
          chainId,
          receiver,
          amount,
          nonce,
          reserveAddress,
          claimFee,
          data,
          [],
          {
            from: alice,
          }
        ),
        "not confirmed"
      );
    });

    it("should reject minting with wrong claim fee", async function() {
      const claimFee = toBN(toWei("20"));
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      await expectRevert(
        this.debridge.autoMint(
          debridgeId,
          chainId,
          receiver,
          amount,
          nonce,
          reserveAddress,
          claimFee,
          data,
          [],
          {
            from: alice,
          }
        ),
        "autoMint: not confirmed"
      );
    });

    it("should reject minting twice", async function() {
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      await expectRevert(
        this.debridge.autoMint(
          debridgeId,
          chainId,
          receiver,
          amount,
          nonce,
          reserveAddress,
          claimFee,
          data,
          [],
          {
            from: alice,
          }
        ),
        "mint: already used"
      );
    });
  });

  context("Test burn method", () => {
    const claimFee = toBN(toWei("1"));
    const data = "0x";

    it("should burning when the amount is suficient", async function() {
      const tokenAddress = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
      const chainIdTo = 56;
      const receiver = alice;
      const amount = toBN(toWei("10"));
      const debridgeId = await this.debridge.getDebridgeId(
        chainIdTo,
        tokenAddress
      );
      const debridge = await this.debridge.getDebridge(debridgeId);
      const wrappedAsset = await WrappedAsset.at(debridge.tokenAddress);
      const balance = toBN(await wrappedAsset.balanceOf(bob));
      await wrappedAsset.approve(this.debridge.address, amount, {
        from: bob,
      });
      const deadline = MAX_UINT256;
      const signature = await permit(
        wrappedAsset,
        bob,
        this.debridge.address,
        amount,
        deadline,
        bobPrivKey
      );
      await this.debridge.autoBurn(
        debridgeId,
        receiver,
        amount,
        chainIdTo,
        reserveAddress,
        claimFee,
        data,
        deadline,
        signature,
        {
          from: bob,
        }
      );
      const newBalance = toBN(await wrappedAsset.balanceOf(bob));
      assert.equal(balance.sub(amount).toString(), newBalance.toString());
      const newDebridge = await this.debridge.getDebridge(debridgeId);
      const supportedChainInfo = await this.debridge.getChainSupport(chainIdTo);

      const fees = toBN(supportedChainInfo.transferFee)
        .mul(amount)
        .div(toBN(toWei("1")))
        .add(toBN(supportedChainInfo.fixedFee));
      assert.equal(
        debridge.collectedFees.add(fees).toString(),
        newDebridge.collectedFees.toString()
      );
    });

    it("should reject burning with no fee", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const chainId = 56;
      const receiver = bob;
      const amount = toBN(toWei("1"));
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const deadline = 0;
      const signature = "0x";
      await expectRevert(
        this.debridge.autoBurn(
          debridgeId,
          receiver,
          amount,
          42,
          reserveAddress,
          0,
          data,
          deadline,
          signature,
          {
            from: alice,
          }
        ),
        "autoBurn: fee too low"
      );
    });

    it("should reject burning with too high fee", async function() {
      const tokenAddress = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
      const chainId = 56;
      const receiver = bob;
      const amount = toBN(toWei("100"));
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const debridge = await this.debridge.getDebridge(debridgeId);
      const wrappedAsset = await WrappedAsset.at(debridge.tokenAddress);
      await wrappedAsset.mint(alice, amount, { from: alice });
      await wrappedAsset.approve(this.debridge.address, amount, {
        from: alice,
      });
      const deadline = 0;
      const signature = "0x";
      await expectRevert(
        this.debridge.autoBurn(
          debridgeId,
          receiver,
          amount,
          chainId,
          reserveAddress,
          toBN(toWei("100")),
          data,
          deadline,
          signature,
          {
            from: alice,
          }
        ),
        "autoBurn: proposed fee too high"
      );
    });

    it("should reject burning from current chain", async function() {
      const tokenAddress = ZERO_ADDRESS;
      const chainId = await this.debridge.chainId();
      const receiver = bob;
      const amount = toBN(toWei("1"));
      const debridgeId = await this.debridge.getDebridgeId(
        chainId,
        tokenAddress
      );
      const deadline = 0;
      const signature = "0x";
      await expectRevert(
        this.debridge.autoBurn(
          debridgeId,
          receiver,
          amount,
          56,
          reserveAddress,
          claimFee,
          data,
          deadline,
          signature,
          {
            from: alice,
          }
        ),
        "burn: native asset"
      );
    });

    //TODO: check 'send: amount does not cover fees' when pay by token
    // it("should reject burning too few tokens", async function() {
    //   const tokenAddress = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
    //   const chainId = 56;
    //   const receiver = bob;
    //   const amount = toBN(toWei("0.1"));
    //   const debridgeId = await this.debridge.getDebridgeId(
    //     chainId,
    //     tokenAddress
    //   );
    //   const deadline = 0;
    //   const signature = "0x";
    //   await expectRevert(
    //     this.debridge.autoBurn(
    //       debridgeId,
    //       receiver,
    //       amount,
    //       chainId,
    //       reserveAddress,
    //       claimFee,
    //       data,
    //       deadline,
    //       signature,
    //       {
    //         from: alice,
    //       }
    //     ),
    //     "burn: amount too low"
    //   );
    // });
  });

  context("Test claim method", () => {
    const tokenAddress = ZERO_ADDRESS;
    const receiver = bob;
    const amount = toBN(toWei("0.8"));
    const nonce = 4;
    const claimFee = toBN(toWei("0.1"));
    const data = "0x";
    let chainIdFrom = 50;
    let chainId;
    let debridgeId;
    let outsideDebridgeId;
    let erc20DebridgeId;
    before(async function() {
      chainId = await this.debridge.chainId();
      debridgeId = await this.debridge.getDebridgeId(chainId, tokenAddress);
      outsideDebridgeId = await this.debridge.getDebridgeId(
        56,
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"
      );
      erc20DebridgeId = await this.debridge.getDebridgeId(
        chainId,
        this.mockToken.address
      );
      const cuurentChainSubmission = await this.debridge.getAutoSubmisionId(
        debridgeId,
        chainIdFrom,
        chainId,
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      await this.aggregator.submit(cuurentChainSubmission, {
        from: bob,
      });
      const outsideChainSubmission = await this.debridge.getAutoSubmisionId(
        outsideDebridgeId,
        chainIdFrom,
        56,
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      await this.aggregator.submit(outsideChainSubmission, {
        from: bob,
      });
      const erc20Submission = await this.debridge.getAutoSubmisionId(
        erc20DebridgeId,
        chainIdFrom,
        chainId,
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      await this.aggregator.submit(erc20Submission, {
        from: bob,
      });
    });

    it("should claim native token when the submission is approved", async function() {
      const debridge = await this.debridge.getDebridge(debridgeId);
      const balance = toBN(await web3.eth.getBalance(receiver));
      await this.debridge.autoClaim(
        debridgeId,
        chainIdFrom,
        receiver,
        amount,
        nonce,
        reserveAddress,
        claimFee,
        data,
        {
          from: alice,
        }
      );
      const newBalance = toBN(await web3.eth.getBalance(receiver));
      const submissionId = await this.debridge.getAutoSubmisionId(
        debridgeId,
        chainIdFrom,
        await this.debridge.chainId(),
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      const isSubmissionUsed = await this.debridge.isSubmissionUsed(
        submissionId
      );
      const newDebridge = await this.debridge.getDebridge(debridgeId);
      assert.equal(balance.add(amount).toString(), newBalance.toString());
      assert.equal(
        debridge.collectedFees.toString(),
        newDebridge.collectedFees.toString()
      );
      assert.ok(isSubmissionUsed);
    });

    it("should claim ERC20 when the submission is approved", async function() {
      const debridge = await this.debridge.getDebridge(erc20DebridgeId);
      const balance = toBN(await this.mockToken.balanceOf(receiver));
      await this.debridge.autoClaim(
        erc20DebridgeId,
        chainIdFrom,
        receiver,
        amount,
        nonce,
        reserveAddress,
        claimFee,
        data,
        {
          from: alice,
        }
      );
      const newBalance = toBN(await this.mockToken.balanceOf(receiver));
      const submissionId = await this.debridge.getAutoSubmisionId(
        erc20DebridgeId,
        chainIdFrom,
        await this.debridge.chainId(),
        amount,
        receiver,
        nonce,
        reserveAddress,
        claimFee,
        data
      );
      const isSubmissionUsed = await this.debridge.isSubmissionUsed(
        submissionId
      );
      const newDebridge = await this.debridge.getDebridge(erc20DebridgeId);
      assert.equal(balance.add(amount).toString(), newBalance.toString());
      assert.equal(
        debridge.collectedFees.toString(),
        newDebridge.collectedFees.toString()
      );
      assert.ok(isSubmissionUsed);
    });

    it("should reject claiming with unconfirmed submission", async function() {
      const nonce = 1;
      await expectRevert(
        this.debridge.autoClaim(
          debridgeId,
          chainIdFrom,
          receiver,
          amount,
          nonce,
          reserveAddress,
          claimFee,
          data,
          {
            from: alice,
          }
        ),
        "autoClaim: not confirmed"
      );
    });

    it("should reject claiming the token from outside chain", async function() {
      await expectRevert(
        this.debridge.autoClaim(
          outsideDebridgeId,
          chainIdFrom,
          receiver,
          amount,
          nonce,
          reserveAddress,
          claimFee,
          data,
          {
            from: alice,
          }
        ),
        "autoClaim: not confirmed"
      );
    });

    it("should reject claiming twice", async function() {
      await expectRevert(
        this.debridge.autoClaim(
          debridgeId,
          chainIdFrom,
          receiver,
          amount,
          nonce,
          reserveAddress,
          claimFee,
          data,
          {
            from: alice,
          }
        ),
        "claim: already used"
      );
    });
  });
});
