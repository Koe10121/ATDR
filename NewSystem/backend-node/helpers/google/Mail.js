const nodemailer = require("nodemailer");

function cleanString(value) {
    return value == null ? '' : String(value).trim();
}

function normalizeSmtp(options) {
    const smtp = options && options.smtp ? options.smtp : (options || {});
    const host = cleanString(smtp.host);
    const port = Number(smtp.port || 587);
    const user = cleanString(smtp.user);
    const pass = cleanString(smtp.pass);
    return {
        host: host,
        port: Number.isFinite(port) ? port : 587,
        secure: typeof smtp.secure === 'boolean' ? smtp.secure : port === 465,
        user: user,
        pass: pass
    };
}

function hasUsableCredentials(smtp) {
    return !!(
        smtp &&
        cleanString(smtp.host) &&
        cleanString(smtp.user) &&
        cleanString(smtp.pass) &&
        !cleanString(smtp.user).startsWith('replace-with-') &&
        !cleanString(smtp.pass).startsWith('replace-with-')
    );
}

function getMailConfig(options) {
    const smtp = normalizeSmtp(options);
    return {
        host: smtp.host,
        port: smtp.port,
        secure: smtp.secure,
        auth: {
            user: smtp.user,
            pass: smtp.pass
        }
    };
}

function getFromAddress(options) {
    const smtp = normalizeSmtp(options);
    const address = cleanString(options && options.from) || smtp.user;
    const name = cleanString(options && options.fromName) || cleanString(options && options.appName) || "NewSystem";
    return name && address ? `"${name}" <${address}>` : address;
}

exports.isConfigured = function (options) {
    return hasUsableCredentials(normalizeSmtp(options));
};

exports.hasUsableCredentials = function (smtp) {
    return hasUsableCredentials(normalizeSmtp(smtp));
};

exports.sendMail = async function (to, subject, text, html, options) {
    const smtp = normalizeSmtp(options);
    if (!hasUsableCredentials(smtp)) {
        return { success: false, error: new Error('smtp_not_configured') };
    }

    const transporter = nodemailer.createTransport(getMailConfig({ smtp: smtp }));
    let mailOptions = {
        from: getFromAddress(Object.assign({}, options, { smtp: smtp })),
        to,
        subject,
        text,
        html,
    };
    if (options && options.replyTo) {
        mailOptions.replyTo = options.replyTo;
    }

    try {
        let info = await transporter.sendMail(mailOptions);
        console.log("Mail sent: %s", info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error("Error sending mail:", error);
        return { success: false, error };
    }
}
