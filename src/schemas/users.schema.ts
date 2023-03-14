import * as bcrypt from 'bcrypt';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

export type UserDocument = User & Document;

@Schema()
export class User {
  @Prop({ required: true })
  name: string;
  @Prop({ required: true, unique: true })
  username: string;
  @Prop({ required: true, unique: true })
  email: string;
  @Prop({ required: true })
  password: string;
  @Prop()
  refreshToken: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre('save', async function (next) {
  try {
    const hashed = await bcrypt.hash(this.password, 10);

    this.password = hashed;

    return next();
  } catch (err) {
    return next(err);
  }
});

UserSchema.pre('findOneAndUpdate', async function (next) {
  try {
    const refreshToken = this.get('refreshToken');
    if (refreshToken) {
      const hashed = await bcrypt.hash(refreshToken, 16);
      this.set({ refreshToken: hashed });
    }

    return next();
  } catch (err) {
    return next(err);
  }
});

UserSchema.set('toJSON', {
  transform: function (doc, ret) {
    delete ret['password'];
    return ret;
  },
});
