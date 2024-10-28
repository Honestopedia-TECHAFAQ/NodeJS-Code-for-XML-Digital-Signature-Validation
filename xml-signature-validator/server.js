const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const { DOMParser } = require('xmldom');
const { SignedXml } = require('xmldsigjs');

const app = express();
const port = 3000;
const upload = multer({ dest: 'uploads/' });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
const validateSignature = async (filePath) => {
  const xml = fs.readFileSync(filePath, 'utf8');
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, 'text/xml');

  try {
    const signedXml = new SignedXml();
    const signatureNode = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];

    if (!signatureNode) {
      return { success: false, message: 'No signature found' };
    }
    signedXml.loadSignature(signatureNode);
    const valid = await signedXml.checkSignature(xml);

    if (!valid) {
      return { success: false, message: 'Signature is not valid' };
    }
    const cert = signedXml.keyInfoProvider.getCert();
    if (!cert) {
      return { success: false, message: 'Certificate not found' };
    }
    const certificate = parseCertificate(cert);

    return {
      success: true,
      certificateDetail: {
        organization: certificate.organization,
        issuer: certificate.issuer,
        validTo: certificate.validTo,
      },
    };
  } catch (err) {
    return { success: false, message: err.message };
  }
};
const parseCertificate = (cert) => {
  return {
    organization: 'Dummy Organization',
    issuer: 'Dummy Issuer',
    validTo: '2024-12-31',
  };
};
app.post('/upload', upload.single('xmlFile'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  const result = await validateSignature(req.file.path);
  fs.unlinkSync(req.file.path); 

  res.json(result);
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
