import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';

@Injectable()
export class DeviceIdPipe implements PipeTransform<string, string> {
  transform(value: string) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(value)) {
      throw new BadRequestException('Invalid device id');
    }
    return value;
  }
}
