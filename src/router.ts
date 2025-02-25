import { Router } from 'itty-router'
import credentials_router from './api/routes/credentials'
import store_router from './api/routes/store'
import error_handler from './error_handler'

const router = Router()

router
    .all( '/api/credentials/*', credentials_router.handle)

router.all('/store/*', store_router.handle)

router.all('*', error_handler)

export default router
