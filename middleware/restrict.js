const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');

function restrict() {
  const authError = {
    message: 'invalid creds'
  };
  return async (req, res, next) => {
    try {
      const { username, password } = req.headers;
      // make sure those values are not empty
      if (!username || !password) {
        res.status(401).json(authError);
      }
      const user = await Users.findBy({ username }).first();
      // make sure the user exists
      if (!user) {
        return res.status(401).json(authError);
      }

      const passwordValid = await bcrypt.compare(password, user.password);

      if (!passwordValid) {
        return res.status(401).json(authError);
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = restrict;
