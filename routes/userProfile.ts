/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username && username.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const match = username.match(/#\{([^}]+)\}/)
      if (match) {
        const code = match[1].trim()
        try {
          if (!code) {
            throw new Error('Username is null')
          }
          const singleQuoteRegex = /^'(?:[^'\\]|\\.)*'$/
          const doubleQuoteRegex = /^"(?:[^"\\]|\\.)*"$/
          const numericRegex = /^-?\d+(?:\.\d+)?$/
          const booleanRegex = /^(?:true|false|null|undefined)$/
          const arithmeticRegex = /^[0-9+\-*/%() .]+$/

          const isSafe = singleQuoteRegex.test(code) ||
            doubleQuoteRegex.test(code) ||
            numericRegex.test(code) ||
            booleanRegex.test(code) ||
            arithmeticRegex.test(code)

          if (!isSafe || code.includes('#{') || code.includes('!{') || /\\(?:x0*23|u0*23|x0*7b|u0*7b)/i.test(code)) {
            throw new Error('Unsafe code execution blocked')
          }
          const evaluated = eval(code) // eslint-disable-line no-eval
          if (typeof evaluated === 'string' && (evaluated.includes('#{') || evaluated.includes('!{') || /[\r\n]/.test(evaluated))) {
            throw new Error('Unsafe code execution blocked')
          }
          username = username.replace(match[0], String(evaluated))
        } catch (err) {
          username = user.username
        }
      }
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      const sanitizedUsername = username
        .replace(/[\r\n]+/g, ' ')
        .replace(/\\/g, '\\\\')
        .replace(/#{/g, '\\#{')
        .replace(/!{/g, '\\!{')
      template = template.replace(/_username_/g, () => sanitizedUsername)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      let fn
      try {
        fn = pug.compile(template)
      } catch (compileErr) {
        template = (await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' }))
          .replace(/_username_/g, () => (user?.username ?? '')
            .replace(/[\r\n]+/g, ' ')
            .replace(/\\/g, '\\\\')
            .replace(/#{/g, '\\#{')
            .replace(/!{/g, '\\!{'))
          .replace(/_emailHash_/g, security.hash(user?.email))
          .replace(/_title_/g, entities.encode(config.get<string>('application.name')))
          .replace(/_favicon_/g, favicon())
          .replace(/_bgColor_/g, theme.bgColor)
          .replace(/_textColor_/g, theme.textColor)
          .replace(/_navColor_/g, theme.navColor)
          .replace(/_primLight_/g, theme.primLight)
          .replace(/_primDark_/g, theme.primDark)
          .replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))
        fn = pug.compile(template)
      }
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      try {
        res.send(fn(user))
      } catch (renderErr) {
        template = (await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' }))
          .replace(/_username_/g, () => (user?.username ?? '')
            .replace(/[\r\n]+/g, ' ')
            .replace(/\\/g, '\\\\')
            .replace(/#{/g, '\\#{')
            .replace(/!{/g, '\\!{'))
          .replace(/_emailHash_/g, security.hash(user?.email))
          .replace(/_title_/g, entities.encode(config.get<string>('application.name')))
          .replace(/_favicon_/g, favicon())
          .replace(/_bgColor_/g, theme.bgColor)
          .replace(/_textColor_/g, theme.textColor)
          .replace(/_navColor_/g, theme.navColor)
          .replace(/_primLight_/g, theme.primLight)
          .replace(/_primDark_/g, theme.primDark)
          .replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))
        fn = pug.compile(template)
        res.send(fn(user))
      }
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
