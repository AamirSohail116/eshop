import { NextFunction, Request, Response } from "express";
import bcrypt from 'bcryptjs'
import { checkOtpRestrictions, sendOtp, trackOtpRequests, validationRegistrationData, verifyOtp } from "../utils/auth.helper";
import prisma from "../../../../packages/libs/prisma";
import { ValidationError } from "../../../../packages/error-handler";

// Regitser a new user
export const userRegistration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        validationRegistrationData(req.body, "user")
        const { name, email } = req.body


        const existingUser = await prisma.user.findUnique({
            where: { email }
        })

        if (existingUser) {
            return next(new ValidationError("User already exist with this eamil!"))
        }

        await checkOtpRestrictions(email, next)
        await trackOtpRequests(email, next)
        await sendOtp(name, email, "user-activation-mail")

        res.status(200).json({
            message: "OTp send to mail. Please verify your account"
        })
    } catch (error) {
        return next(error)
    }

}

export const verifyUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, otp, password, name } = req.body

        if (!email || !otp || !password || !name) {
            return next(new ValidationError("All fields are required"))
        }

        const existingUser = await prisma.user.findUnique({ where: { email } })
        if (existingUser) {
            return next(new ValidationError("User already exist"))
        }

        await verifyOtp(email, otp, next)

        const hashedPassword = await bcrypt.hash(password, 10)

        await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword
            }
        })

        res.status(200).json({
            success: true,
            message: "User register successfully"
        })
    } catch (error) {
        return next(error)
    }
}