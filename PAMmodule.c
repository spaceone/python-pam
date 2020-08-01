/*
 * PAMmodule.c
 *
 * Python PAM module
 *
 * Copyright (c) 1999, 2006 Rob Riggs and tummy.com, Ltd. All rights reserved.
 * Released under GNU LGPL version 2.1.
 */

static char revision[] = "$Id: PAMmodule.c,v 1.3 2007/04/18 03:55:11 rob Exp $";

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <Python.h>
#include <stdio.h>
#include <dlfcn.h>

static PyObject *PyPAM_Error;

typedef struct {
    PyObject_HEAD
    struct pam_conv     *conv;
    pam_handle_t        *pamh;
    char                *service;
    char                *user;
    PyObject            *callback;
    struct pam_response *response_data;
    int                 response_len;
    PyObject            *user_data;
    void                *dlh1, *dlh2;
} PyPAMObject;

staticforward PyTypeObject PyPAMObject_Type;

static void PyPAM_Err(PyPAMObject *self, int result)
{
    PyObject            *error;
    const char          *err_msg;

    err_msg = pam_strerror(self->pamh, result);
    error = Py_BuildValue("(si)", err_msg, result);
    Py_INCREF(PyPAM_Error);
    PyErr_SetObject(PyPAM_Error, error);
}

static int PyPAM_conv(int num_msg, const struct pam_message **msg,
    struct pam_response **resp, void *appdata_ptr)
{
    PyObject                *args;

    PyPAMObject* self = (PyPAMObject *) appdata_ptr;
    if (self->callback == NULL)
        return PAM_CONV_ERR;

    Py_INCREF(self);

    if (NULL != self->response_data) {
        for (int i = 0; i < self->response_len; i++) {
            free(self->response_data[0].resp);
        }
        free(self->response_data);
        self->response_data = NULL;
        self->response_len = 0;
    }

    PyObject* msgList = PyList_New(num_msg);
    
    for (int i = 0; i < num_msg; i++) {
        PyList_SetItem(msgList, i,
            Py_BuildValue("(si)", msg[i]->msg, msg[i]->msg_style));
    }
    
    args = Py_BuildValue("(OO)", self, msgList);
    PyObject* respList = PyEval_CallObject(self->callback, args);
    Py_DECREF(args);
    Py_DECREF(self);
    
    if (respList == NULL)
        return PAM_CONV_ERR;

    if (!PyList_Check(respList)) {
        Py_DECREF(respList);
        return PAM_CONV_ERR;
    }
    
    *resp = (struct pam_response *) malloc(
        PyList_Size(respList) * sizeof(struct pam_response));

    struct pam_response* spr = *resp;
    for (int i = 0; i < PyList_Size(respList); i++, spr++) {
        PyObject* respTuple = PyList_GetItem(respList, i);
        char* resp_text;
        int resp_retcode = 0;
        if (!PyArg_ParseTuple(respTuple, "si", &resp_text, &resp_retcode)) {
            free(*resp);
            Py_DECREF(respList);
            return PAM_CONV_ERR;
        }
        spr->resp = strdup(resp_text);
        spr->resp_retcode = resp_retcode;
        Py_DECREF(respTuple);
    }
    
    // Save this so we can free it later.
    self->response_data = *resp;
    self->response_len = PyList_Size(respList);

    Py_DECREF(respList);
    
    return PAM_SUCCESS;
}

static struct pam_conv default_conv = {
    misc_conv,
    NULL
};

static struct pam_conv python_conv = {
    PyPAM_conv,
    NULL
};

static PyObject * PyPAM_pam(PyObject *self, PyObject *args)
{
    PyPAMObject             *p;
    struct pam_conv         *spc;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_TypeError, "pam() takes no arguments");
        return NULL;
    }

    PyPAMObject_Type.ob_type = &PyType_Type;
    p = (PyPAMObject *) PyObject_NEW(PyPAMObject, &PyPAMObject_Type);

    if ((spc = (struct pam_conv *) malloc(sizeof(struct pam_conv))) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "out of memory");
        return NULL;
    }

    p->conv = spc;
    p->pamh = NULL;
    p->service = NULL;
    p->user = NULL;
    Py_INCREF(Py_None);
    p->callback = Py_None;
    p->response_data = NULL;
    p->response_len = 0;
    Py_INCREF(Py_None);
    p->user_data = Py_None;
    
    p->dlh1 = dlopen("libpam.so", RTLD_LAZY | RTLD_GLOBAL);
    p->dlh2 = dlopen("libpam_misc.so", RTLD_LAZY | RTLD_GLOBAL);

    return (PyObject *) p;
}

static PyObject * PyPAM_start(PyObject *self, PyObject *args)
{
    int                 result;
    char                *service = NULL, *user = NULL;
    PyObject            *callback = NULL;
    PyPAMObject         *_self = (PyPAMObject *) self;

    if (!PyArg_ParseTuple(args, "s|zO", &service, &user, &callback)) {
        PyErr_SetString(PyExc_TypeError, "start(service, [user, [callback]])");
        return NULL;
    }

    if (callback != NULL && !PyCallable_Check(callback)) {
        PyErr_SetString(
            PyExc_TypeError,
            "the callback parameter must be a function"
        );
        return NULL;
    }

    if (service) _self->service = strdup(service);
    if (user) _self->user = strdup(user);

    Py_DECREF(_self->callback);
    if (callback) {
        Py_INCREF(callback);
        _self->callback = callback;
        memcpy(_self->conv, &python_conv, sizeof(struct pam_conv));
        _self->conv->appdata_ptr = (void *) self;
    } else {
        Py_INCREF(Py_None);
        _self->callback = Py_None;
        memcpy(_self->conv, &default_conv, sizeof(struct pam_conv));
    }

    result = pam_start(_self->service, _self->user, _self->conv, &_self->pamh);

    if (result != PAM_SUCCESS) {
        PyPAM_Err(_self, result);
        return NULL;
    }

    Py_INCREF(Py_None);

    return Py_None;
}

static PyObject * PyPAM_authenticate(PyObject *self, PyObject *args)
{
    int                    result, flags = 0;
    PyPAMObject*           _self = (PyPAMObject*) self;
    
    if (!PyArg_ParseTuple(args, "|i", &flags)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be integer");
        return NULL;
    }
    
    result = pam_authenticate(_self->pamh, flags);
    
    if (result != PAM_SUCCESS) {
        PyPAM_Err(_self, result);
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_setcred(PyObject *self, PyObject *args)
{
    int                    result, flags = 0;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "i", &flags)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be integer");
        return NULL;
    }
    
    result = pam_setcred(_self->pamh, flags);
    
    if (result != PAM_SUCCESS) {
        PyErr_SetString(PyPAM_Error, "Not authenticated");
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_acct_mgmt(PyObject *self, PyObject *args)
{
    int                    result, flags = 0;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "|i", &flags)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be integer");
        return NULL;
    }
    
    result = pam_acct_mgmt(_self->pamh, flags);
    
    if (result != PAM_SUCCESS) {
        PyErr_SetString(PyPAM_Error, "Not authenticated");
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_chauthtok(PyObject *self, PyObject *args)
{
    int                    result, flags = 0;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "|i", &flags)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be integer");
        return NULL;
    }
    
    result = pam_chauthtok(_self->pamh, flags);
    
    if (result != PAM_SUCCESS) {
        PyErr_SetString(PyPAM_Error, "Not authenticated");
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_open_session(PyObject *self, PyObject *args)
{
    int                    result, flags = 0;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "|i", &flags)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be integer");
        return NULL;
    }
    
    result = pam_open_session(_self->pamh, flags);
    
    if (result != PAM_SUCCESS) {
        PyErr_SetString(PyPAM_Error, "Not authenticated");
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_close_session(PyObject *self, PyObject *args)
{
    int                    result, flags = 0;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "|i", &flags)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be integer");
        return NULL;
    }
    
    result = pam_close_session(_self->pamh, flags);
    
    if (result != PAM_SUCCESS) {
        PyErr_SetString(PyPAM_Error, "Not authenticated");
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_set_item(PyObject *self, PyObject *args)
{
    int                 result, item;
    char                *s_val, *n_val;
    PyObject            *o_val;
    PyPAMObject         *_self = (PyPAMObject *) self;
    
    if (PyArg_ParseTuple(args, "is", &item, &s_val)) {
        n_val = strdup(s_val);
        if (item == PAM_USER)
            _self->user = n_val;
        if (item == PAM_SERVICE)
            _self->service = n_val;
        result = pam_set_item(_self->pamh, item, (void *) n_val);
    } else {
        // An error occured parsing the tuple.  Clear it.  Then try to parse
        // it a different way.
        PyErr_Clear();
        if (PyArg_ParseTuple(args, "iO:set_callback", &item, &o_val)) {
            if (item == PAM_CONV && !PyCallable_Check(o_val)) {
                PyErr_SetString(PyExc_TypeError, "parameter must be a function");
                return NULL;
            } else {
                Py_XDECREF(_self->callback);
                _self->callback = o_val;
                Py_INCREF(_self->callback);
                memcpy(_self->conv, &python_conv, sizeof(struct pam_conv));
                _self->conv->appdata_ptr = (void *) self;
                result = pam_set_item(_self->pamh, item, (void *) _self->conv);
            }
        } else {
            PyErr_SetString(PyExc_TypeError, "bad parameter");
            return NULL;
        }
    }

    if (result != PAM_SUCCESS) {
        PyPAM_Err(_self, result);
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_get_item(PyObject *self, PyObject *args)
{
    int                    result, item;
    const void            *val;
    PyObject            *retval;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "i", &item)) {
        PyErr_SetString(PyExc_TypeError, "bad parameter");
        return NULL;
    }
    
    result = pam_get_item(_self->pamh, item, &val);
    
    if (result != PAM_SUCCESS) {
        PyPAM_Err(_self, result);
        return NULL;
    }
    
    if (item == PAM_CONV)
        retval = Py_BuildValue("O:set_callback", val);
    else
        retval = Py_BuildValue("s", val);


    return retval;
}

static PyObject * PyPAM_putenv(PyObject *self, PyObject *args)
{
    int                    result;
    char                *val;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "s", &val)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be a string");
        return NULL;
    }
    
    result = pam_putenv(_self->pamh, val);
    
    if (result != PAM_SUCCESS) {
        PyErr_SetString(PyPAM_Error, "Not authenticated");
        return NULL;
    }

    Py_INCREF(Py_None);
    
    return Py_None;
}

static PyObject * PyPAM_getenv(PyObject *self, PyObject *args)
{
    const char          *result, *val;
    PyObject            *retval;
    PyPAMObject         *_self = (PyPAMObject *) self;
    
    if (!PyArg_ParseTuple(args, "s", &val)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be a string");
        return NULL;
    }
    
    result = pam_getenv(_self->pamh, val);
    
    if (result == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    retval = Py_BuildValue("s", result);
    
    return retval;
}

static PyObject * PyPAM_getenvlist(PyObject *self, PyObject *args)
{
    char                **result, *cp;
    PyObject            *retval, *entry;
    PyPAMObject            *_self = (PyPAMObject *) self;
    
    result = pam_getenvlist(_self->pamh);
    
    if (result == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    retval = PyList_New(0);
    
    while ((cp = *(result++)) != NULL) {
        entry = Py_BuildValue("s", cp);
        PyList_Append(retval, entry);
        Py_DECREF(entry);
    }
    
    return retval;
}

static PyObject * PyPAM_set_userdata(PyObject *self, PyObject *args)
{
    PyPAMObject     *_self = (PyPAMObject *) self;
    PyObject        *user_data;

    if (!PyArg_ParseTuple(args, "O", &user_data)) {
        PyErr_SetString(
            PyExc_TypeError,
            "set_userdata() expects exactly 1 argument"
        );
        return NULL;
    }

    Py_DECREF(_self->user_data);
    Py_INCREF(user_data);
    _self->user_data = user_data;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject * PyPAM_get_userdata(PyObject *self, PyObject *args)
{
    PyPAMObject     *_self = (PyPAMObject *) self;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(
            PyExc_TypeError,
            "get_userdata() takes no arguments"
        );
        return NULL;
    }

    Py_INCREF(_self->user_data);
    return _self->user_data;
}

static PyMethodDef PyPAMObject_Methods[] = {
    {"start", PyPAM_start, METH_VARARGS, NULL},
    {"authenticate", PyPAM_authenticate, METH_VARARGS, NULL},
    {"setcred", PyPAM_setcred, METH_VARARGS, NULL},
    {"acct_mgmt", PyPAM_acct_mgmt, METH_VARARGS, NULL},
    {"chauthtok", PyPAM_chauthtok, METH_VARARGS, NULL},
    {"open_session", PyPAM_open_session, METH_VARARGS, NULL},
    {"close_session", PyPAM_close_session, METH_VARARGS, NULL},
    {"set_item", PyPAM_set_item, METH_VARARGS, NULL},
    {"get_item", PyPAM_get_item, METH_VARARGS, NULL},
    {"putenv", PyPAM_putenv, METH_VARARGS, NULL},
    {"getenv", PyPAM_getenv, METH_VARARGS, NULL},
    {"getenvlist", PyPAM_getenvlist, METH_VARARGS, NULL},
    {"set_userdata", PyPAM_set_userdata, METH_VARARGS, NULL},
    {"get_userdata", PyPAM_get_userdata, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static void PyPAM_dealloc(PyPAMObject *self)
{
    free(self->service);
    free(self->user);
    free(self->conv);
    pam_end(self->pamh, PAM_SUCCESS);
    dlclose(self->dlh2);
    dlclose(self->dlh1);
    PyMem_DEL(self);
}

static PyObject * PyPAM_getattr(PyPAMObject *self, char *name)
{
    return Py_FindMethod(PyPAMObject_Methods, (PyObject *) self, name);
}

static PyObject * PyPAM_repr(PyPAMObject *self)
{
    char                buf[1024];
    
    snprintf(buf, 1024, "<pam object, service=\"%s\", user=\"%s\", conv=%p, pamh=%p>",
        self->service, self->user, self->conv, self->pamh);
    return PyString_FromString(buf);
}

static PyTypeObject PyPAMObject_Type = {
    PyObject_HEAD_INIT(0)    /* Must fill in type value later */
    0,
    "pam",
    sizeof(PyPAMObject),
    0,
    (destructor)PyPAM_dealloc,        /*tp_dealloc*/
    0,        /*tp_print*/
    (getattrfunc)PyPAM_getattr,        /*tp_getattr*/
    0,        /*tp_setattr*/
    0,        /*tp_compare*/
    (reprfunc)PyPAM_repr,            /*tp_repr*/
    0,        /*tp_as_number*/
    0,        /*tp_as_sequence*/
    0,        /*tp_as_mapping*/
};

static PyMethodDef PyPAM_Methods[] = {
    {"pam", PyPAM_pam, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static char PyPAMObject_doc[] = "";

/* Convenience routine to export an integer value.
 *
 * Errors are silently ignored, for better or for worse...
 * Happily borrowed from Python's socketmodule.c
 */
static void insint(PyObject *d, char *name, int value)
{
    PyObject*        v = PyInt_FromLong((long) value);

    if (!v || PyDict_SetItemString(d, name, v))
        PyErr_Clear();

    Py_XDECREF(v);
}

void initPAM(void)
{
    PyObject            *m, *d;

    m = Py_InitModule("PAM", PyPAM_Methods);
    d = PyModule_GetDict(m);
    
    PyPAM_Error = PyErr_NewException("PAM.error", NULL, NULL);
    if (PyPAM_Error == NULL)
        return;
    PyDict_SetItemString(d, "error", PyPAM_Error);

    PyPAMObject_Type.ob_type = &PyType_Type;
    PyPAMObject_Type.tp_doc = PyPAMObject_doc;
    Py_INCREF(&PyPAMObject_Type);

    insint(d, "PAM_SUCCESS", PAM_SUCCESS);
    insint(d, "PAM_OPEN_ERR", PAM_OPEN_ERR);
    insint(d, "PAM_SYMBOL_ERR", PAM_SYMBOL_ERR);
    insint(d, "PAM_SERVICE_ERR", PAM_SERVICE_ERR);
    insint(d, "PAM_SYSTEM_ERR", PAM_SYSTEM_ERR);
    insint(d, "PAM_BUF_ERR", PAM_BUF_ERR);
    insint(d, "PAM_PERM_DENIED", PAM_PERM_DENIED);
    insint(d, "PAM_AUTH_ERR", PAM_AUTH_ERR);
    insint(d, "PAM_CRED_INSUFFICIENT", PAM_CRED_INSUFFICIENT);
    insint(d, "PAM_AUTHINFO_UNAVAIL", PAM_AUTHINFO_UNAVAIL);
    insint(d, "PAM_USER_UNKNOWN", PAM_USER_UNKNOWN);
    insint(d, "PAM_MAXTRIES", PAM_MAXTRIES);
    insint(d, "PAM_NEW_AUTHTOK_REQD", PAM_NEW_AUTHTOK_REQD);
    insint(d, "PAM_ACCT_EXPIRED", PAM_ACCT_EXPIRED);
    insint(d, "PAM_SESSION_ERR", PAM_SESSION_ERR);
    insint(d, "PAM_CRED_UNAVAIL", PAM_CRED_UNAVAIL);
    insint(d, "PAM_CRED_EXPIRED", PAM_CRED_EXPIRED);
    insint(d, "PAM_CRED_ERR", PAM_CRED_ERR);
    insint(d, "PAM_NO_MODULE_DATA", PAM_NO_MODULE_DATA);
    insint(d, "PAM_CONV_ERR", PAM_CONV_ERR);
    insint(d, "PAM_AUTHTOK_ERR", PAM_AUTHTOK_ERR);
    insint(d, "PAM_AUTHTOK_RECOVER_ERR", PAM_AUTHTOK_RECOVER_ERR);
    insint(d, "PAM_AUTHTOK_LOCK_BUSY", PAM_AUTHTOK_LOCK_BUSY);
    insint(d, "PAM_AUTHTOK_DISABLE_AGING", PAM_AUTHTOK_DISABLE_AGING);
    insint(d, "PAM_TRY_AGAIN", PAM_TRY_AGAIN);
    insint(d, "PAM_IGNORE", PAM_IGNORE);
    insint(d, "PAM_ABORT", PAM_ABORT);
    insint(d, "PAM_AUTHTOK_EXPIRED", PAM_AUTHTOK_EXPIRED);
    insint(d, "PAM_MODULE_UNKNOWN", PAM_MODULE_UNKNOWN);
    insint(d, "PAM_BAD_ITEM", PAM_BAD_ITEM);
    insint(d, "_PAM_RETURN_VALUES", _PAM_RETURN_VALUES);

    insint(d, "PAM_SILENT", PAM_SILENT);
    insint(d, "PAM_DISALLOW_NULL_AUTHTOK", PAM_DISALLOW_NULL_AUTHTOK);
    insint(d, "PAM_ESTABLISH_CRED", PAM_ESTABLISH_CRED);
    insint(d, "PAM_DELETE_CRED", PAM_DELETE_CRED);
    insint(d, "PAM_REINITIALIZE_CRED", PAM_REINITIALIZE_CRED);
    insint(d, "PAM_REFRESH_CRED", PAM_REFRESH_CRED);
    insint(d, "PAM_CHANGE_EXPIRED_AUTHTOK", PAM_CHANGE_EXPIRED_AUTHTOK);

    insint(d, "PAM_SERVICE", PAM_SERVICE);
    insint(d, "PAM_USER", PAM_USER);
    insint(d, "PAM_TTY", PAM_TTY);
    insint(d, "PAM_RHOST", PAM_RHOST);
    insint(d, "PAM_CONV", PAM_CONV);
    /* These next two are most likely not needed for client apps */
    insint(d, "PAM_RUSER", PAM_RUSER);
    insint(d, "PAM_USER_PROMPT", PAM_USER_PROMPT);

    insint(d, "PAM_DATA_SILENT", PAM_DATA_SILENT);

    insint(d, "PAM_PROMPT_ECHO_OFF", PAM_PROMPT_ECHO_OFF);
    insint(d, "PAM_PROMPT_ECHO_ON", PAM_PROMPT_ECHO_ON);
    insint(d, "PAM_ERROR_MSG", PAM_ERROR_MSG);
    insint(d, "PAM_TEXT_INFO", PAM_TEXT_INFO);
#ifdef __LINUX__
    insint(d, "PAM_RADIO_TYPE", PAM_RADIO_TYPE);
    insint(d, "PAM_BINARY_MSG", PAM_BINARY_MSG);
    insint(d, "PAM_BINARY_PROMPT", PAM_BINARY_PROMPT);
#endif

}
