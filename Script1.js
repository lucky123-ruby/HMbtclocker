// JavaScript source code
const express = require('express');
const axios = require('axios');
const app = express();
const port = 3000;

// 设置你创建的比特币钱包地址
const walletAddress = 'YOUR_WASABI_WALLET_ADDRESS';  // 这里是 Wasabi Wallet 生成的比特币地址
const requiredAmount = 0.001;  // 例如：0.001 BTC
const blockcypherAPIKey = 'YOUR_BLOCKCYPHER_API_KEY'; // 从 Blockcypher 获取你的 API Key

// Blockcypher API URL
const blockcypherAPIUrl = `https://api.blockcypher.com/v1/btc/main/addrs/${walletAddress}/full?token=${blockcypherAPIKey}`;

app.get('/check-payment', async (req, res) => {
    try {
        // 调用 Blockcypher API 查询交易
        const response = await axios.get(blockcypherAPIUrl);

        let paymentReceived = false;

        // 检查交易记录中是否存在足够金额的支付
        response.data.txs.forEach(tx => {
            tx.outputs.forEach(output => {
                if (output.value / 1e8 >= requiredAmount) {  // value是单位是Satoshis，所以除以1e8
                    paymentReceived = true;
                }
            });
        });

        res.json({ paymentReceived });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: '检查支付失败' });
    }
});

app.listen(port, () => {
    console.log(`服务器正在监听 http://localhost:${port}`);
});
npm install axios
node server.js

