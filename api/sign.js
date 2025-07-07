// Importa o módulo 'crypto' nativo do Node.js
const crypto = require('crypto');

// A função principal que a Vercel irá executar
export default async function handler(request, response) {
  // --- 1. Validação de Segurança ---
  // Verifica se a requisição é um POST
  if (request.method !== 'POST') {
    return response.status(405).send('Method Not Allowed');
  }

  // Pega o token secreto do cabeçalho da requisição
  const clientToken = request.headers['x-auth-token'];
  // Pega o token secreto configurado nas Variáveis de Ambiente da Vercel
  const serverToken = process.env.AUTH_TOKEN;

  // Valida se o token foi enviado e se é o correto
  if (!clientToken || clientToken !== serverToken) {
    return response.status(401).send('Unauthorized'); // Resposta de não autorizado
  }

  // --- 2. Extrai os dados enviados pelo n8n ---
  const { asin, partnerTag } = request.body;

  if (!asin || !partnerTag) {
    return response.status(400).send('Missing asin or partnerTag');
  }

  // --- 3. Pega as credenciais da Amazon das Variáveis de Ambiente ---
  const accessKey = process.env.AMAZON_ACCESS_KEY;
  const secretKey = process.env.AMAZON_SECRET_KEY;
  const host = 'webservices.amazon.com.br';
  const region = 'us-east-1';

  // --- 4. Lógica de Assinatura SigV4 (a mesma que tentamos no n8n) ---
  const service = 'ProductAdvertisingAPI';
  const algorithm = 'AWS4-HMAC-SHA256';
  const amzTarget = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.GetItems';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').substr(0, 15) + 'Z';
  const dateStamp = amzDate.substr(0, 8);

  const payload = {
    "ItemIds": [asin],
    "PartnerTag": partnerTag,
    "PartnerType": "Associates",
    "Resources": ["Images.Primary.Large", "ItemInfo.Title", "Offers.Listings.Price"]
  };
  const payloadString = JSON.stringify(payload);
  const hashedPayload = crypto.createHash('sha256').update(payloadString).digest('hex');
  const canonicalURI = '/paapi5/getitems';
  const canonicalQuerystring = '';
  const canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\nx-amz-target:${amzTarget}\n`;
  const signedHeaders = 'host;x-amz-date;x-amz-target';
  const canonicalRequest = `POST\n${canonicalURI}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;
  const hashedCanonicalRequest = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${hashedCanonicalRequest}`;

  const kDate = crypto.createHmac('sha256', 'AWS4' + secretKey).update(dateStamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update('paapi5').digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  // --- 5. Retorna os dados para o n8n ---
  response.status(200).json({
    authorizationHeader: authorizationHeader,
    amzDate: amzDate,
    amzTarget: amzTarget,
    payload: payload
  });
}
