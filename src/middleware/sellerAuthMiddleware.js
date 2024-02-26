const jwt = require('jsonwebtoken');
const config = require('../Connection/jwt');
const secretKey = config.seller.secretKey;


const authenticateSellerToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, decodedSeller) => {
    if (err) return res.sendStatus(403);

    req.seller = decodedSeller; // Attach the decoded seller object to the request object
    next();
  });
};


module.exports = {
  authenticateSellerToken,
};
