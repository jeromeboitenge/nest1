import { Injectable, UnauthorizedException, ForbiddenException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";

export interface JwtPayload {
    sub: string;
    email: string;
    userRole: string; // example roles: "admin", "user"
}

@Injectable()
export class VerifyTokenService {
    constructor(private readonly jwtService: JwtService) { }

    // Verify token validity
    async verify(token: string) {
        try {
            const payload = await this.jwtService.verifyAsync<JwtPayload>(token);
            return { valid: true, payload };
        } catch {
            throw new UnauthorizedException("Invalid or expired token");
        }
    }

    // ✅ Check token and ensure user has specific role
    async verifyWithRole(token: string, requiredRole: string) {
        try {
            const payload = await this.jwtService.verifyAsync<JwtPayload>(token);

            if (payload.userRole !== requiredRole) {
                throw new ForbiddenException(
                    `Access denied: requires ${requiredRole} role`
                );
            }

            return { valid: true, payload };
        } catch (error) {
            if (error instanceof ForbiddenException) throw error;
            throw new UnauthorizedException("Invalid or expired token");
        }
    }
}
