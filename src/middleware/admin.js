'use strict';

const nconf = require('nconf');
const user = require('../user');
const meta = require('../meta');
const plugins = require('../plugins');
const privileges = require('../privileges');
const helpers = require('./helpers');

const controllers = {
	admin: require('../controllers/admin'),
	helpers: require('../controllers/helpers'),
};

const middleware = module.exports;

middleware.buildHeader = helpers.try(async (req, res, next) => {
	res.locals.renderAdminHeader = true;
	if (req.method === 'GET') {
		await require('./index').applyCSRFasync(req, res);
	}

	res.locals.config = await controllers.admin.loadConfig(req);
	next();
});

middleware.checkPrivileges = helpers.try(async (req, res, next) => {
	if (isGuest(req, res)) {
		return;
	}

	const path = req.path.replace(/^(\/api)?(\/v3)?\/admin\/?/g, '');
	if (!(await hasPrivilegeForPath(req, path))) {
		return controllers.helpers.notAllowed(req, res);
	}

	if (!await userHasPassword(req)) {
		return next();
	}

	if (shouldRelogin(req)) {
		await handleRelogin(req, res);
	} else {
		extendLogoutTimer(req);
		return next();
	}
});

// Function to check if the user is a guest
function isGuest(req, res) {
	if (req.uid <= 0) {
		controllers.helpers.notAllowed(req, res);
		return true;
	}
	return false;
}

// Function to check if the user has the necessary privilege for the requested path
async function hasPrivilegeForPath(req, path) {
	if (path) {
		const privilege = privileges.admin.resolve(path);
		return await privileges.admin.can(privilege, req.uid);
	} else {
		const privilegeSet = await privileges.admin.get(req.uid);
		return Object.values(privilegeSet).some(Boolean);
	}
}

// Function to check if the user has a password
async function userHasPassword(req) {
	return await user.hasPassword(req.uid);
}

// Function to determine if the user needs to re-login
function shouldRelogin(req) {
	const loginTime = req.session.meta ? req.session.meta.datetime : 0;
	const adminReloginDuration = meta.config.adminReloginDuration * 60000;
	return !(meta.config.adminReloginDuration === 0 || (loginTime && parseInt(loginTime, 10) > Date.now() - adminReloginDuration));
}

// Function to handle user re-login
async function handleRelogin(req, res) {
	let returnTo = req.path;
	if (nconf.get('relative_path')) {
		returnTo = req.path.replace(new RegExp(`^${nconf.get('relative_path')}`), '');
	}
	returnTo = returnTo.replace(/^\/api/, '');

	req.session.returnTo = returnTo;
	req.session.forceLogin = 1;

	await plugins.hooks.fire('response:auth.relogin', { req, res });
	if (!res.headersSent) {
		if (res.locals.isAPI) {
			controllers.helpers.formatApiResponse(401, res);
		} else {
			res.redirect(`${nconf.get('relative_path')}/login?local=1`);
		}
	}
}

// Function to extend the user's logout timer
function extendLogoutTimer(req) {
	const loginTime = req.session.meta ? req.session.meta.datetime : 0;
	const adminReloginDuration = meta.config.adminReloginDuration * 60000;
	const timeLeft = parseInt(loginTime, 10) - (Date.now() - adminReloginDuration);
	if (req.session.meta && timeLeft < Math.min(60000, adminReloginDuration)) {
		req.session.meta.datetime += Math.min(60000, adminReloginDuration);
	}
}