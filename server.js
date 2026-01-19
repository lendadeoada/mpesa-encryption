const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Função de criptografia RSA PKCS1 v1.5
function encryptApiKey(apiKey, publicKeyPem) {
  try {
    console.log('Recebida requisição de criptografia');
    console.log('Tamanho da API Key:', apiKey.length);
    console.log('Public Key (primeiros 100 chars):', publicKeyPem.substring(0, 100));
    
    // Limpar a chave pública
    let pemContents = publicKeyPem
      .replace(/-----BEGIN (?:RSA )?PUBLIC KEY-----/g, '')
      .replace(/-----END (?:RSA )?PUBLIC KEY-----/g, '')
      .replace(/\s/g, '')
      .replace(/\\n/g, '')
      .replace(/\\r/g, '')
      .replace(/"/g, '')
      .replace(/'/g, '');
    
    console.log('PEM limpo, tamanho:', pemContents.length);
    
    // Verificar se precisa de padding base64
    if (pemContents.length % 4 !== 0) {
      pemContents += '='.repeat((4 - pemContents.length % 4) % 4);
    }
    
    // Criptografar usando RSA public key
    const encrypted = crypto.publicEncrypt(
      {
        key: `-----BEGIN PUBLIC KEY-----\n${pemContents}\n-----END PUBLIC KEY-----`,
        padding: crypto.constants.RSA_PKCS1_PADDING
      },
      Buffer.from(apiKey, 'utf-8')
    );
    
    const result = encrypted.toString('base64');
    console.log('Criptografia bem sucedida, tamanho do resultado:', result.length);
    
    return result;
  } catch (error) {
    console.error('Erro detalhado na criptografia:', error);
    throw error;
  }
}

// Rota de criptografia
app.post('/encrypt', (req, res) => {
  try {
    console.log('=== NOVA REQUISIÇÃO DE CRIPTOGRAFIA ===');
    const { apiKey, publicKey } = req.body;
    
    if (!apiKey || !publicKey) {
      console.error('Dados faltando:', { apiKey: !!apiKey, publicKey: !!publicKey });
      return res.status(400).json({ 
        success: false,
        error: 'apiKey e publicKey são obrigatórios' 
      });
    }
    
    const encrypted = encryptApiKey(apiKey, publicKey);
    
    res.json({ 
      success: true, 
      encrypted: encrypted,
      timestamp: new Date().toISOString()
    });
    
    console.log('Requisição processada com sucesso');
    
  } catch (error) {
    console.error('Erro no endpoint /encrypt:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'mpesa-encryption',
    timestamp: new Date().toISOString(),
    nodeVersion: process.version
  });
});

// Rota de teste
app.get('/test', (req, res) => {
  try {
    // Chave pública de TESTE (exemplo)
    const testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyour-test-key-here-1234567890
-----END PUBLIC KEY-----`;
    
    const testApiKey = 'test-api-key-123';
    
    const encrypted = encryptApiKey(testApiKey, testPublicKey);
    
    res.json({ 
      test: 'success', 
      message: 'Serviço de criptografia funcionando',
      encryptedSample: encrypted.substring(0, 50) + '...',
      encryptedLength: encrypted.length 
    });
  } catch (error) {
    res.json({ 
      test: 'failed', 
      error: error.message 
    });
  }
});

// Rota raiz
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>Serviço de Criptografia M-Pesa</title></head>
      <body>
        <h1>Serviço de Criptografia RSA para M-Pesa</h1>
        <p>Este serviço fornece criptografia RSA PKCS1 para API do M-Pesa.</p>
        <ul>
          <li><a href="/health">Health Check</a></li>
          <li><a href="/test">Testar Criptografia</a></li>
        </ul>
        <p>Use POST /encrypt com { "apiKey": "...", "publicKey": "..." }</p>
      </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`=== SERVIDOR INICIADO ===`);
  console.log(`Servidor de criptografia rodando na porta ${PORT}`);
  console.log(`URL: http://localhost:${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Teste: http://localhost:${PORT}/test`);
  console.log(`=========================`);
});
