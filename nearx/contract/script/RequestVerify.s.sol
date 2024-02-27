// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {NearX, decodePackedIds, TransactionOrReceiptId} from "../src/NearX.sol";

// TODO: refactor for 128, taking the input fixture
contract RequestVerify is Script {
    function run() external {
        address mostRecentlyDeployedProxy = DevOpsTools
            .get_most_recent_deployment("ERC1967Proxy", block.chainid);

        bytes
            memory data = hex"009dbbc777884bc0ccc05fc9177bd442e19a9b82608f7ae6c8b81cbadee2320e1c77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01026d02a778ce47a4a670e343cebf90a67309157b2a3a54079c13b8962908b080686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0024e2d4f8d3394fabea1a8ac255ec3ef9c6e14cc90e8e45c1d185f9a858d484107a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c000a594de1c36eca52f15d9f7d4177515570f3a6966e5ac51da1ce4abb7e496c6a706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00311fa837e07749c47b2825d06dd14d3aa6f438e2e1cc69857b737d0104ac080576325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007f454878ba125cc5f380439ee3c3e6510e8d66e7adcb70e59951bcf51c2916d5686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c012c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d797a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0156b47c3c713180318844195b0e0e29810c5f099fe19411eaf116d55b3f6d1f96706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0027d1be4cbf7826333bb3a66339314d6b23088907bc03abe8e1f0402f6b8e99fb6f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006d6c0e7346e597949cf4ef07e57b029426cac6d2a0e80761b07aaa83e5622fe16f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007f4bf0c2de11327648a0b56a170029f349308fc88d64badffaf4b1575a0444056f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00ae58764b2108d1e23de28591a61e52e6fdeb49f0985ab6bf5f332e338db742f877616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c000e7d92ca3c2fbd087783533f3e3c493881189b9e95829763ee2222d5ef50524361737365742d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0010478412784e05112c2ab987ce3d691a1f8d284f5e80d71d573229b6d643563b61737365742d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c009eac5b84d08bbf7716b595fc0d10686ead30355e5b7a8c9305ac02240823513961737365742d6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0124e495308164a0a97925a27e59fadec0c6fc59de23c5ffaef3ff30a2c513d51a686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0133fb9d5f75d87a3cf8eca81ad16c669a686aac61fc514a6cf1159e739618c2e86f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01d6c2a78d92595947756cc38ad2fb077984f691ebbba0d1db03c2cbed071d16ef6f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0133f6198c994c4ca12b360abc226c232f1dd46bef6c5be02c39278b8de8ea04696f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c003d268ee173d6cbe5f0c0efa3833fe6590950938cb7b24b15957587fd0380729375736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c008be60e1ba421b4c0cf104749bd2f322f6d985763053b347bf68c6000908aa693796b616a753261386a6366672e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c002aa060c38662a90fa07a34b800cd3c84360d894dc4bec1c81a7b41d3eb282092706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006674894d631ca3e373a87b27ea614f16468fa9ddaf401f079d93359f14f29f6e72656c61792e6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00bc656c82f3aed97695b555e49b55e584f960197f092a53ac9bcc3f872125436476325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01a988b23956e4e5ab00dd3d16decdd0714554562ae9fbfae9053acca1a91f37cc75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00883c8876a557200a3b14ad46b0646af75750403ab3cb5ff04ef6a72f4f71b7786175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01d916068721ec0d451382e00bebd8f4f713321e3bde850c36463517d6c50115c5706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01bf4b51df07bf9819b996b720eadafc5323ec7a2ad7fc0555190771faaa582d3272656c61792e6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c1e6131d4648085ea2f1e23ba516e6d03a05c6448c30639b1b082c8650544506686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00956fff9f472d68ff61b7c3e88b678738f5082e44ca40277cb394501a86d8b42177616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c005ef99fadc671ee47c6015c92351d2c172995832ac01ecd1e8b8ceae3722ccc296f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c002c0d2c9385d28114166aee120e40fdf5f713f07477e0abd4eb63c7a39da10ac770726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01796847ad9c2cbe2a5006a89dafe3e7838846085f4cd240b97c29d1253a9476c1686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01dcfc4f30c70a7da653f1166a1e4abd70865b0042773485674804591a2d1f001b6f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00094532de95f1fa7fa1ae18fdbe8e09bb98c4e3fbb5033a6b5ae990594569b27775736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c21d9dab00ab7481de442b9d8273dfe151799c66cdf52346a6d9c44c418824306c776a64766c767a666f37392e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c003f185492791bff0827767b40925d34beb5530e55ea6a18cc559a513c96598431706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00af6aecb8c18aeed12c89e10024d7848732c1edc39ac0b47d421c92807d14835c76325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01a25c13eeab4dbb89d8308e148b34c7d52fbb32044c0552da9be982c9b480f22175736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01e99199a0ee36379f8ec381be29fb5429950d7ea2a4e661f9a352d7c2e3f087a6706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0049fcac1e1358c141f432296c655a7f37ad6f799e676b864741e017fa48e1619d6f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c004c55453e68e24a730befcedf4dbf17dcb4522774ebdcdc959bbb8881216f095d6f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00caeed0384fc2e3d27b729993601365870abdeac789239a155b2d2c7c86921ee06f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007366f9850730663c25ad58c7d0b2c92887d5b3521c36627a3f5b0f1cafc23e3d61737365742d6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c008dc95d832842725b8e2dd1752ed1ecbebe0354d7a8b384f6036267433bf8f4f861737365742d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00a2dcd933e13734be2cf545f6f4150a2911041bc4840cd8df25b2e4cfaf84ac4b61737365742d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0045989ff55b321cf17042336002143923eaeb1f7aca1890d06b8661beb5469f4a686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01178da8f0216f3935a7b18792f2f524aaa3e0ce04878be5e88e7374a22588187b6f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c016f7c2658d5db3ad5c21b8cd74b67e3cd88583efbb0990c866eada559459f15296f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01c743450fa747831ab768ff6b81769b99fdf4dd7a96d77b11b4b134746994b2e06f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00e1d64d332912d157d409dd7b2cd15922d1458c9f89db1a6aaec788722c8c9feb77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01376545409c923b585549e2775ea44f17cf666c8a96b7f46000470ce8215cc29f686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00bb801a7742b42c0a63572de86a669f4278cbfd2ad83890a78aca8927c5c559a8706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0025effa5cf9769e5e4ee9ea894e96e5fa7f8d2d3e02779afb093c71bfd191c0b175736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c67d9883f54fdbe34cb4eca5ebea3bd11eb1c643759bfd68312fe30a5538860876325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c1f41e50f9b71459d5e937ab570c7ff6eff9c1ca59c58512fb4442de7435160637337576793879366b7872382e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01fbbdfc15d6cc230ad33560005bd260d319c55b740e974f2670556660bcb1b569706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01450b4cd2c1041e86dd7131ff0d0565112eb9a6eddf472ab0e40f117fae2e9e1b75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00a51296de1fa4bdb501f5e22e70bd7357c311eb96c480c7b5a83b0c73cac3a3a56f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00ada0187c6e035b3726b80677a4dfe0b580ec9bf6fbea5ad9ddc5334377e4bd0f686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006970f24b1c8d919325a5bf853410ed55ce3ebd1c7d209b7f44a4125ac9192b4a77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0051d453f91d122400d4ffea377689f251447437e4e870a159be8d3e9604b21e9c70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01b2bd890c05c3af200de1cd245cff4156daf7109813703e9642423b3e5c721967686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01d9ce54d510d4c9c42931dcd9e46ff5c8253ad86e3e0a8aa2803d7698f2f123c06f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00bcb5dba2c2640610b8d0189cd7a545c1082261aac92bfef5ed36771f16cb925075736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c003c2ef2b1d44fc0f6a8952dd90894737519c9ae1687b9641c43cc3c7e69eae62c6474617a7a317336777465322e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00f6f1bc126b85da0b9413c839d94cf0753e933ee94e59112b3755769ab15091866f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c005e6cdecba3c18cd8df4504fcce70585d95224e8cb9536584bce3de584f6af6116f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00ba78aeb2fefc974b28b920d55d2272067e520ef9c7bda33d190be43f8e5331d96f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c018debe92ce04dae79f833258017ee1ecac7d32b7772c3489db3f382a9fdf0dc5275736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0092ac8da13b7eb470beb940aefe3113cb1691ea11699fffc0a90e34dfb5ba02ae61737365742d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00a5fb923fa82b73f48c911ebff4595c0a86f4cb7f7ca3d54387da724f0d6e316d61737365742d6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006420a00089b6c26f96f900f1422e95a1b5dca6b4664e8c8057a8ce49e7c2dc6f61737365742d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01b875da1c575c2e1254103f3633918084fe49012d2e528e2cc0061e1e30bd3d286f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01f6eb39a6fff73ba199ce13195d9b61461239d32217941ed26e45c74a651b93876f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c017bddbe92024918efcc2187f0f1cf02d5f08c1410131742965b1618dca217dd376f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00a59b1ab3a8038c1185fffdab48360c18011c6b334767abaf573aa8976edac890686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007d0eec60dded5c4f117c27cf63139ab6c19e918736acc0c52be3edfb6a65b0ce77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0090ef5aefc01261767eb94d1a3cb59dd73b20c01e5ff9f55e4b463f07247e8d3c706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01e40d099c2e6883cd319aaf52b3b29d43305d069484017f8dbe6d1e6dfb0945a6686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00dba102a52675cc53f8176ea91727afcbcfdbe9d0ea1a595a34f869357086e2db76325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007235081eba3164d3a3079bf54dca800270b8f8f7f2ac4b8b7b23b3bc199de22c75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00e2d28a4d3a035cb1ac7860c98c9727361995622667df5199fec7be4288932b4e7a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0153fc02f4e7ccb921d3416493d27b55624b320a2d38c5b9f61a6048451e0206a9706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00d166b618dce48f4a119a14abca9f85181a67016596916a22063530537f01ce5e313266626831676c636761742e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0074d2fd7d043d81e094fb01cccc56b1e65490a890eb32c78c0bb7dc60dff76abc70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c018359b2a6712f088e072ad798f7c09bedfe82f79963a31a1b4258553107d67bd575736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01b5e9920a135036cfd2af5b8959b91eec0010e60fe6161551517a7babd941436b7a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c000bab00c39618436abebd736b23681eee010d8698d76e674a4b74774a9340ad5f686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c009c917c130c06c09904bb4fa785134c6620540b3e514c0eb6dc46d0d2eb4d0c1c706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0030ae7beef7ef03cb7a8e7272f31caa776a811ea14baf2f88166e153a091eea9177616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00d2977d006dc76464f3fff3c0d79ee8e272cff2ede29ce5435abf20e434b981c776325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01b1397b648ffbe568f0948c663de51478ee59ea7f9650ddc66385ec82d999332f686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01eac41dbd9e4ac61e6563807449cf6c24373a0a9d936d4c0460d434e9e5686e56706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00108e67bad908a8d93ad2ad11237b14a7213ba72dd94fd12cfd7634cccec030376f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00398683f803de41db53ba1fb3ce05f1b16ce00acd3b63a13ed8848a4b472375c16f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c000d71a4926cfa09f4209c5733b9930b2487d6153cd442b53867c0b914069cf8d075736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00e3227be1fff28d7f6a8e2f60550060b522edd9fa2525e6d38fb772cc62181a7f6f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0078a53eab5a1761e01aefba7655d437a386a96c603efb2bc55d15c67effc5f8b761737365742d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0044cb39b104c68014193ab25802fe3bd6193ca6fa27b978975244a092e9ddd00261737365742d6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00e7ff3a76008fba50478f67a8632fcd210a925ca93916ead39ef2f24df9f04c9336386672647269613439766d2e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00e9af93fb98c6eb6eeb6c3488626c7c879454d84ec8b3ca773431d606fc705ae961737365742d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c008ca8cfea66a0d9c8620fda8254dcab2939f2e35f1516032e6a86d1fa5937fd60732d6c616d312e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0026cfd72efde1617a80c0e1150a4dd9e1d1a4649b5135413c2ae0dcfb699a224870726963652d6f7261636c652d76312e6e6561726c656e642d6f6666696369616c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c016d6b45b053655e9e9cc076cda1c36a678276de517fbdddc0b38664d4c8abc7f96f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0183d42a5fe196260fc9a9ee3902030bdd443b6417fdf3772312ea73fe64cc56986f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c017a804a4b16015ea05f501a0eecb47777428beb383ad2fbe090e62d499c2e6a3675736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01b4082a419e23b30b701aa1345b9de41ca0763a3a46e6839029cf51bc8ee92be76f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c018f31d24f72c4bb135ffdb56f022723cf284add497c5ec0e016c94830422d2086732d6c616d312e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00f776278d1a804f9d9ed5b803f77720907b3b07af6eb47869aa26a884dcb95360706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00032072129958d50ab29289651f84af960adc57cbd09afa6231466f50323d75d2686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0076d6768b9a80c969e557e465ce259b7b3c40c8c6c0dfb33e26b07c1c0bbf541072656c61792e6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00314203fbdc85f52832e2b026322a23393adccf428d262c8d83cf495e2ad8d17077616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006d41ac0ddbbb3f4fef405ad78337ea1ed1745df288cfd8a0bde449a04beea7ba76325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00882758a173b262a6c607e80a59ac1553dcc57c4cfdc63e9fa98d2344acbffa2f746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00ccf5eac51a1b6e57fd2605a80773c6a432769c8e142a2a3ef72462e131b76f48746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007a2c6c982ab354c4448948a2bef0f86d353dda983ae3dd810c81e8fd0dc53a2d6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01f2dac06800a69fa823fb11fb44cf520cd1c8475ec23cab10204dfb3e2e720bf0686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01a96d55bf23fc006afdfd3ce4334fa0eb6969192b0b34e628fb64b12b2ae23f5f706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006ebce1b1a64ddb3849beabf354e62829bfcbdcaed484e17ca26b298bcab71e226465762d313730353330373935343733322d32333231323236313631323538342c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00d1553da94dcee551b0834725f2ab762e936b332f24ac962fb3f4b73e99163a636465762d313730353330373935343731362d32363030353632313832303036312c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01afdca85f436fafadc675a42f9c6d9c1f1d6454eca062c83fc1e0690e5381ba8a72656c61792e6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c019fc084d6c408f3369330354027e008ac5a83cc83606d99e200d0f4b14a74f8dc746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c013192067f557baa41444430c749bb7dc241d238dae5be85bcd4615f86ae13ae26746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0070ff84e558f127c26d63ca4e7d26fe62d490b71c9187bae3b3fee13c6ca7f55075736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00203ca6c4a7c5e60fe8fa95adf12682dbf891c7cf164ea52e4e177516889c21b57676746a716868666e726c322e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c013b6dcc41f7c0df9e45c1aa2602488a5075f2b7f73013d9e3096622c3cfdd1dff75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";
        TransactionOrReceiptId[] memory ids = decodePackedIds(data);

        vm.startBroadcast();

        NearX proxy = NearX(payable(mostRecentlyDeployedProxy));
        proxy.requestVerify(ids);

        vm.stopBroadcast();
    }
}
