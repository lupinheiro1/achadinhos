import { createSigner } from 'fast-aws-signer';

// Handler function for the API route
export default async function handler(req, res) {
  // Simple auth check to protect your endpoint
  const authToken = req.headers['x-auth-token'];
  if (authToken !== process.env.AUTH_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // ====================== PONTO DA CORREÇÃO ======================
  // 1. Receber os novos campos do corpo da requisição do n8n
  const { asin, partnerTag, Marketplace, Operation } = req.body;

  // Validação para garantir que todos os campos chegaram
  if (!asin || !partnerTag || !Marketplace || !Operation) {
    return res.status(400).json({ error: 'Missing required fields in body: asin, partnerTag, Marketplace, Operation' });
  }
  // =============================================================

  // Get credentials from environment variables
  const accessKeyId = process.env.AMAZON_ACCESS_KEY;
  const secretAccessKey = process.env.AMAZON_SECRET_KEY;

  if (!accessKeyId || !secretAccessKey) {
    return res.status(500).json({ error: 'Server configuration error: Amazon credentials not set' });
  }
  
  // Define service details consistent with Scratchpad
  const service = 'ProductAdvertisingAPI';
  const region = 'us-east-1';
  const host = 'webservices.amazon.com.br';
  const method = 'POST';
  const path = '/paapi5/getitems';
  const amzTarget = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.GetItems';

  // ====================== PONTO DA CORREÇÃO ======================
  // 2. Montar o payload final INCLUINDO os novos campos
  const payload = {
    ItemIds: [asin],
    PartnerTag: partnerTag,
    PartnerType: "Associates",
    Marketplace: Marketplace, // <-- Adicionado
    Operation: Operation,     // <-- Adicionado
    Resources: [
      "Images.Primary.Large",
      "ItemInfo.Title",
      "Offers.Listings.Price"
    ]
  };
  // =============================================================

  const payloadString = JSON.stringify(payload);

  // Create a signer instance
  const sign = createSigner({
    accessKeyId,
    secretAccessKey,
    region,
    service,
  });

  // Generate the signature
  const signature = sign({
    method,
    host,
    path,
    headers: {
      'x-amz-target': amzTarget,
      'content-encoding': 'amz-1.0',
    },
    body: payloadString,
  });

  // Send back the required headers and the *complete* payload
  res.status(200).json({
    authorizationHeader: signature.headers.Authorization,
    amzDate: signature.headers['X-Amz-Date'],
    amzTarget: amzTarget,
    payload: payload, // Agora este payload estará completo
  });
}
