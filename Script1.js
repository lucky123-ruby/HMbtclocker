// JavaScript source code
const express = require('express');
const axios = require('axios');
const app = express();
const port = 3000;

// �����㴴���ı��ر�Ǯ����ַ
const walletAddress = 'YOUR_WASABI_WALLET_ADDRESS';  // ������ Wasabi Wallet ���ɵı��رҵ�ַ
const requiredAmount = 0.001;  // ���磺0.001 BTC
const blockcypherAPIKey = 'YOUR_BLOCKCYPHER_API_KEY'; // �� Blockcypher ��ȡ��� API Key

// Blockcypher API URL
const blockcypherAPIUrl = `https://api.blockcypher.com/v1/btc/main/addrs/${walletAddress}/full?token=${blockcypherAPIKey}`;

app.get('/check-payment', async (req, res) => {
    try {
        // ���� Blockcypher API ��ѯ����
        const response = await axios.get(blockcypherAPIUrl);

        let paymentReceived = false;

        // ��齻�׼�¼���Ƿ�����㹻����֧��
        response.data.txs.forEach(tx => {
            tx.outputs.forEach(output => {
                if (output.value / 1e8 >= requiredAmount) {  // value�ǵ�λ��Satoshis�����Գ���1e8
                    paymentReceived = true;
                }
            });
        });

        res.json({ paymentReceived });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: '���֧��ʧ��' });
    }
});

app.listen(port, () => {
    console.log(`���������ڼ��� http://localhost:${port}`);
});
npm install axios
node server.js

