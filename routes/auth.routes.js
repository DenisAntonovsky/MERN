const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/user')
const router = Router()

router.post(
    '/register',
    [
        check('email', 'Incorrect email').isEmail(),
        check('password', 'Long of password must been 6 or simbols').isLength({ min: 6 })
    ], 
    async (req, res) => {    
    try {   
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                errors: errors.array(),
                message: 'Incorrect data on registration'
             })
        }
        
        const {email, password} = req.body

        const condidate = await User.findOne({ email })

        if (condidate) {
            return res.status(400).json({ message: 'Такой пользователь уже существует' })
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword })

        await user.save()

        res.status(201).json({ message: 'Пользоваель создан' })


    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'We have a problem' })
    }
})

router.post(
    '/login',
    [
        check('email', 'Entry correct email').normalizeEmail().isEmail(),
        check('password', 'Entry password please').exists()
    ], 
    async (req, res) => {
    try {   
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                errors: errors.array(),
                message: 'Incorrect data on entring'
                })
        }       
    
        const {email, password} = req.body

        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ message: 'User is not find in DataBase' })
        }

        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(400).json({ message: 'Entry password is incorrect' })
        }

        const token = jwt.sign(
            { userId: user.id },
            config.get('jwtSecret'),
            { expiresIn: '1h' }
        )

        res.json({ token, userId: user.id })

    } catch (error) {                
        res.status(500).json({ message: 'Что-то пошло не так' })
    }
})

module.exports = router
