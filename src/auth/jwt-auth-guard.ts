import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from "@nestjs/common";
import { Request } from "express";

import { JwtPayload, VerifyTokenService } from "./verify-token.service";

interface AuthenticatedRequest extends Request {
    user?: JwtPayload; // replace `any` with your user payload type if available
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private readonly verifyTokenService: VerifyTokenService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
        const authHeader = request.headers["authorization"];

        if (!authHeader) {
            throw new UnauthorizedException("Authorization header missing");
        }

        const [, accessToken] = authHeader.split(" ");

        if (!accessToken) {
            throw new UnauthorizedException("Token missing");
        }

        const result = await this.verifyTokenService.verify(accessToken);
        request.user = result.payload;
        return true;
    }
}