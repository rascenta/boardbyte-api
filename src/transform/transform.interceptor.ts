import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  statusCode: number;
  message: string;
  data: T;
}

@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, Response<T>>
{
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    return next.handle().pipe<Response<T>>(
      map<any, Response<T>>((data: { message: string; result: T }) => ({
        statusCode: context.switchToHttp().getResponse().statusCode,
        message: data.message,
        data: data.result,
      })),
    );
  }
}
