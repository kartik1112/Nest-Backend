import { Controller, Body, Post, UseGuards, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { AuthService } from './auth.service';
import { UserDto } from '../users/user.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('login')
    async login(@Body() body) {
        console.log(body);
        return await this.authService.login(body);
    }

    @Post('signup')
    async signUp(@Body() user: UserDto) {
        return await this.authService.create(user);
    }
}

// public async login(user){
    //     const dbUser = await this.userService.findOneByEmail(user.email);
    //     const checkVal = await this.comparePassword(user.password, dbUser.password);
    //     if (checkVal){
    //         const token = this.generateToken(dbUser);
    //         return{user, token};
    //     }
    //     else {
    //         throw new HttpException('enter valid entry', 400);
    //     }
    // }