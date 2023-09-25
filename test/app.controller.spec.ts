//npm test app.controller

import { Test } from '@nestjs/testing';
import { AppController } from 'src/app.controller';
import { AppService } from './../src/app.service';

describe('AppController', () => {
  let controller;
  let service;

  beforeEach(async () => {
    let module = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
    }).compile();

    controller = module.get(AppController);
    service = module.get(AppService);
  });

  describe('hello', () => {
    it('returns a default message', () => {
      jest.spyOn(service, 'getHello').mockReturnValue('Hello~');
      expect(controller.hello()).toEqual({ message: 'Hello~' });
      expect(service.getHello).toBeCalledTimes(1);
      expect(service.getHello).toBeCalledWith('World');
    });

    it('returns a personalize message', () => {
      jest.spyOn(service, 'getHello').mockReturnValue('Hey, John~');
      expect(controller.hello('John')).toEqual({ message: 'Hey, John~' });
      expect(service.getHello).toBeCalledTimes(1);
      expect(service.getHello).toBeCalledWith('John');
    });
  });
});
