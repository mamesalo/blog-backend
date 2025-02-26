const bycrpt = require("bcryptjs");

const validateUserInput = (username, email, password) => {
  return email && password && username;
};

const comparePassword = (password, hashedPassword) => {
  return bycrpt.compareSync(password, hashedPassword);
};

module.exports = {
  validateUserInput,
  comparePassword,
};
