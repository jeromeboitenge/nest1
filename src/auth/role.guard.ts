import {
    Injectable,
    CanActivate,
    ExecutionContext,
    ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './role.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!requiredRoles) {
            return true; // no role required
        }

        const { user } = context.switchToHttp().getRequest();

        if (!user) {
            throw new ForbiddenException('Access denied: no user found in request');
        }

        if (!requiredRoles.includes(user.userRole)) {
            // 🧩 Return a more specific message showing required roles and user’s role
            throw new ForbiddenException(
                `Access denied: requires one of [${requiredRoles.join(
                    ', '
                )}] roles. Your role is '${user.userRole}'.`
            );
        }

        return true;
    }
}
