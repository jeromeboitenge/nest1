import { IsEmail, IsNotEmpty, IsString, isString } from "class-validator";


export class CreateUserDto {
    @IsString()
    @IsNotEmpty()
    name !: string


    @IsEmail()
    @IsNotEmpty()
    email !: string

    @IsNotEmpty()
    password !: string
}
