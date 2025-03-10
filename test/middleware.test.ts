import { Request, Response, NextFunction } from 'express';
import admin from '../config/firebaseAdmin';
import authenticate from '../src/api/v1/middleware/authenticate';
import isAuthorized from '../src/api/v1/middleware/authorize';
import { AuthenticationError, AuthorizationError } from '../src/api/v1/middleware/authenticate';

type MockedAdminModule = {
    auth: () => {
      verifyIdToken: jest.Mock;
      getUser: jest.Mock;
    };
    verifyIdTokenMock: jest.Mock;
};