const passport = require("passport");

exports.isAuth = (req, res, done) => {
  return passport.authenticate("jwt");
};

exports.sanitizeUser = (user) => {
  return { id: user.id, role: user.role };
};

exports.cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies["jwt"];
  }
  // token =
  // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1Njg5NzZkODRiNDZiOWE1ODE1NTBkYiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzAxMzUzMzYyfQ.r4GuUvanet7ghqLhqZnayEmGWVF-RMiHmaEHHGyF2L4";
  return token;
};
