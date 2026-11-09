package mail

import (
	"bytes"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"unicode"
)

// Every email has a plain-text and an HTML version. The link carries the token
// in the URL *fragment* ("#token=..."), which browsers never send to a server
// and never put in a Referer header, so the token cannot leak to third-party
// resources on the page it opens. The token is printed too, for pasting into
// an API client.

var (
	verifyText = texttemplate.Must(texttemplate.New("vt").Parse(`Hi,

Confirm your email address for {{.App}} by opening this link:

{{.Link}}

Or enter this code in the app: {{.Token}}

The link works once and expires in {{.Expires}}. If you did not create an account, ignore this email.
`))
	verifyHTML = htmltemplate.Must(htmltemplate.New("vh").Parse(`<!doctype html>
<html><body style="font-family:sans-serif;line-height:1.5">
<p>Hi,</p>
<p>Confirm your email address for <strong>{{.App}}</strong>:</p>
<p><a href="{{.Link}}" style="display:inline-block;padding:10px 16px;background:#111;color:#fff;border-radius:6px;text-decoration:none">Confirm email</a></p>
<p>Or enter this code in the app: <code>{{.Token}}</code></p>
<p style="color:#666">The link works once and expires in {{.Expires}}. If you did not create an account, ignore this email.</p>
</body></html>
`))
	resetText = texttemplate.Must(texttemplate.New("rt").Parse(`Hi,

Someone asked to reset the password for your {{.App}} account. To choose a new one, open this link:

{{.Link}}

Or enter this code in the app: {{.Token}}

The link works once and expires in {{.Expires}}. Resetting signs you out everywhere.
If you did not ask for this, ignore this email; your password has not changed.
`))
	resetHTML = htmltemplate.Must(htmltemplate.New("rh").Parse(`<!doctype html>
<html><body style="font-family:sans-serif;line-height:1.5">
<p>Hi,</p>
<p>Someone asked to reset the password for your <strong>{{.App}}</strong> account.</p>
<p><a href="{{.Link}}" style="display:inline-block;padding:10px 16px;background:#111;color:#fff;border-radius:6px;text-decoration:none">Choose a new password</a></p>
<p>Or enter this code in the app: <code>{{.Token}}</code></p>
<p style="color:#666">The link works once and expires in {{.Expires}}. Resetting signs you out everywhere.
If you did not ask for this, ignore this email; your password has not changed.</p>
</body></html>
`))
)

type tplData struct {
	App, Link, Token, Expires string
}

// SafeName makes an application name safe for a subject line and plain text:
// control characters (including line breaks) are dropped.
func SafeName(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
}

func render(txt *texttemplate.Template, h *htmltemplate.Template, d tplData) (string, string) {
	var t, hh bytes.Buffer
	_ = txt.Execute(&t, d)
	_ = h.Execute(&hh, d) // html/template escapes App, Link and Token for their contexts
	return t.String(), hh.String()
}

// VerificationEmail builds the "confirm your email" message. link is the full
// URL (with the token in the fragment); token is repeated for manual entry.
func VerificationEmail(to, appName, link, token, expires string) Message {
	app := SafeName(appName)
	text, html := render(verifyText, verifyHTML, tplData{App: app, Link: link, Token: token, Expires: expires})
	return Message{To: to, Subject: "Confirm your email for " + app, Text: text, HTML: html}
}

// PasswordResetEmail builds the "reset your password" message.
func PasswordResetEmail(to, appName, link, token, expires string) Message {
	app := SafeName(appName)
	text, html := render(resetText, resetHTML, tplData{App: app, Link: link, Token: token, Expires: expires})
	return Message{To: to, Subject: "Reset your " + app + " password", Text: text, HTML: html}
}
