import * as mongoose from 'mongoose';
import * as bcrypt from 'bcrypt';
export const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: {
    type: String,
    select: false,
  },
});

UserSchema.pre('save', async function (next) {
  try {
    const hashed = await bcrypt.hash(this.password, 10);

    this.password = hashed;
    return next();
  } catch (err) {
    return next(err);
  }
});
