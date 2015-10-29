/*
 * Copyright (C) 2015 Deutsche Telekom AG.
 *
 * Author: Mislav Novakovic <mislav.novakovic@sartura.hr>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freenetconfd/plugin.h>
#include <freenetconfd/datastore.h>
#include <freenetconfd/freenetconfd.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"

__unused struct module *init();
__unused void destroy();
datastore_t root = DATASTORE_ROOT_DEFAULT;
datastore_t *extension = NULL;
char *_ns = "urn:ietf:params:xml:ns:yang:sip";
static struct uci_context *context;
char *config_file = "asterisk";
struct module m;

static void init_config_file(char *filename)
{
	struct stat buffer;

	if (0 != stat (filename, &buffer)) {
		FILE *fh = fopen(filename, "w");
		fclose(fh);
	}
}

static datastore_t *find_sibling(datastore_t *self, char *name, char *value)
{
	datastore_t *left = self;
	while (left->prev)
		left = left->prev;
	return ds_find_sibling(left, name, value);
}

int rpc_start(struct rpc_data *data)
{
	pid_t pid=fork();
	if (pid==0) {
		execl("/etc/init.d/asterisk", "asterisk", "start", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return RPC_OK;
}

int rpc_stop(struct rpc_data *data)
{
	pid_t pid=fork();
	if (pid==0) {
		execl("/etc/init.d/asterisk", "asterisk", "stop", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return RPC_OK;
}

int rpc_restart(struct rpc_data *data)
{
	pid_t pid=fork();
	if (pid==0) {
		execl("/etc/init.d/asterisk", "asterisk", "restart", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return RPC_OK;
}

int rpc_reload(struct rpc_data *data)
{
	pid_t pid=fork();
	if (pid==0) {
		execl("/etc/init.d/asterisk", "asterisk", "reload", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return RPC_OK;
}

int rpc_disable(struct rpc_data *data)
{
	pid_t pid=fork();
	if (pid==0) {
		execl("/etc/init.d/asterisk", "asterisk", "disable", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return RPC_OK;
}

int rpc_enable(struct rpc_data *data)
{
	pid_t pid = fork();
	if (pid == 0) {
		execl("/etc/init.d/asterisk", "asterisk", "enable", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

	return RPC_OK;
}

static int list_set_node(datastore_t *self, char *value)
{
	datastore_t *node = ds_find_child(self->parent->parent, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	datastore_t *tmp = self;
	int i = 0;

	while(tmp->prev) {
		i++;
		tmp = tmp->prev;
	}

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + strlen(value) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		return uci_list_set_value(context, &uci[0], value, i);
	} else {
		int len = strlen(config_file) + strlen(option) + strlen(element) + strlen(value) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		return uci_list_set_value(context, &uci[0], value, i);
	}
}

static char *list_get_node(datastore_t *self)
{
	datastore_t *node = find_sibling(self->parent, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	char *result = NULL;
	datastore_t *tmp = self;
	int i = 0;

	while(tmp->prev) {
		i++;
		tmp = tmp->prev;
	}

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		result = uci_list_get(context, &uci[0], i);
	} else {
		int len = strlen(config_file) + strlen(option) + strlen(element) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		result = uci_list_get(context, &uci[0], i);
	}

	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		char *buffer = strdup("");
		return buffer;
	}
}

static int list_del_node(struct datastore *self, void *data)
{
	datastore_t *node = find_sibling(self->parent, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	datastore_t *tmp = self;
	int i = 0;

	while(tmp->prev) {
		i++;
		tmp = tmp->prev;
	}

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		return uci_list_del(context, &uci[0], i);
	} else {
		int len = strlen(config_file) + strlen(option) + strlen(element) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		return uci_list_del(context, &uci[0], i);
	}
}

static int set_node(datastore_t *self, char *value)
{
	datastore_t *node = find_sibling(self, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + strlen(value) + 8;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s=%s", config_file, self->parent->name, element, value);
		return uci_set_value(context, &uci[0]);
	} else {
		int len = strlen(config_file) + strlen(option) + strlen(element) + strlen(value) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s=%s", config_file, option, element, value);
		return uci_set_value(context, &uci[0]);
	}
}

static char *get_node(datastore_t *self)
{
	datastore_t *node = find_sibling(self, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	char *result = NULL;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		result = uci_get(context, &uci[0]);
	} else {
		int len = strlen(config_file) + strlen(option) + strlen(element) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		result = uci_get(context, &uci[0]);
	}

	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		char *buffer = strdup("");
		return buffer;
	}
}

static int del_node(struct datastore *self, void *data)
{
	datastore_t *node = find_sibling(self, "name", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		return uci_del(context, &uci[0]);
	} else {
		int len = strlen(config_file) + strlen(option) + strlen(element) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		return uci_del(context, &uci[0]);
	}
}

static int config_set_node(datastore_t *self, char *value)
{
	struct uci_context *ctx;
	struct uci_package *pack = NULL;
	struct uci_ptr ptr = { 0 };
	int ret;

	if (!value || !strcmp(value, "")) {
		ctx = uci_alloc_context();
		if (!ctx)
			return 1;

		ret = uci_load(ctx, config_file, &pack);
		if (UCI_OK != ret) {
			uci_free_context(ctx);
			return 1;
		}

		ptr.p = pack;
		uci_add_section(ctx, pack, self->parent->name, &ptr.s);
		ptr.o = NULL;

		if (uci_save(context, ptr.p) != UCI_OK) {
			printf("UCI save error.\n");
			uci_free_context(ctx);
			return 1;
		}
		if (uci_commit(context, &ptr.p, 1) != UCI_OK) {
			printf("UCI commit error.\n");
			uci_free_context(ctx);
			return 1;
		}

		uci_free_context(ctx);
		return 0;
	}

	int len = strlen(config_file) + strlen(self->parent->name) + strlen(value) + 3;
	char uci[len];
	snprintf(uci, len, "%s.%s=%s", config_file, value, self->parent->name);

	return uci_set_value(context, &uci[0]);
}

static char *config_get_node(datastore_t *self)
{
	char *option = self->value;
	char *result = NULL;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + 6;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0]", config_file, self->parent->name);
		result = uci_get(context, &uci[0]);
	} else {
		result = strdup(option);
	}

	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		char *buffer = strdup("");
		return buffer;
	}
}

static int config_del_node(struct datastore *self, void *data)
{
	if (!self)
		return 0;
	char *option = self->value;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->name) + 6;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0]", config_file, self->parent->name);
		return uci_del(context, &uci[0]);
	} else {
		int len = strlen(config_file) + strlen(option) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s", config_file, option);
		return uci_del(context, &uci[0]);
	}
}

static int config_del_all_nodes(struct datastore *self, void *data)
{
	int ret = 0;
	datastore_t *tmp = self;
	if (!strcmp(self->name, "extension"))
		tmp = self->child;

	do {
		datastore_t *name = find_sibling(tmp->child, "name", NULL);
		ret = config_del_node(name, NULL);
		tmp = tmp->next;
	} while (tmp);


	return ret;
}

static datastore_t *list_create_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	child->set = list_set_node;
	child->get = list_get_node;
	child->del = list_del_node;
	child->is_list = 1;

	return child;
}

static datastore_t *create_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;
	datastore_t *rings = ds_find_sibling(self->child, "rings", NULL);

	if (!strcmp(name, "rings")) {
		rings = ds_add_child_create(self, "rings", NULL, NULL, NULL, 0);
		rings->create_child = list_create_node;
		return rings;
	}

	//TODO move this code
	if (!strcmp(name, "ring")) {
		if (!rings) {
			rings = ds_add_child_create(self, "rings", NULL, NULL, NULL, 0);
			rings->create_child = list_create_node;
		}
		child = rings->create_child(rings, "ring", value, NULL, NULL, 0);
		child->is_list = 1;
		return child;
	} else {
		child = ds_add_child_create(self, name, value, NULL, NULL, 0);
	}

	if (!strcmp(name, "name")) {
		child->set = config_set_node;
		child->get = config_get_node;
		child->del = config_del_node;
		child->is_key = 1;
	} else {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	}

	return child;
}

static datastore_t *create_section_node(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;

	if (!strcmp(name, "extension")) {
		extension = ds_add_child_create(self, name, NULL, NULL, NULL, 0);
		extension->create_child = create_section_node;
		return extension;
	}

	if (!strcmp(name, "ext")) {
		child = ds_add_child_create(extension, name, NULL, _ns, NULL, 0);
		child->is_list = 1;
	} else {
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
	}

	child->del = config_del_all_nodes;

	child->create_child = create_node;
	return child;
}


static int create_store()
{
	struct uci_context *uci;
	struct uci_package *asterisk = NULL;
	struct uci_element *e, *el, *el_list;
	struct uci_section *s;
	struct uci_option *o, *o_list;
	char *name, *type;
	int i = 0;
	int rc = 0;

	init_config_file("/etc/config/asterisk");

	uci = uci_alloc_context();
	if (!uci)
		return -1;

	if (uci_load(uci, config_file, &asterisk) != UCI_OK) {
		uci_free_context(uci);
		return -1;
	}

	datastore_t *node = NULL;
	root.create_child = create_section_node;

	extension = root.create_child(&root, "extension", NULL, NULL, NULL, 0);
	extension->create_child = create_section_node;
	extension->del = config_del_all_nodes;

	uci_foreach_element(&asterisk->sections, e) {
		s = uci_to_section(e);
		type = s->type;
		name = s->e.name;

		if (s->anonymous)
			name = "";
		--i;
		node = root.create_child(&root, s->type, NULL, _ns, NULL, 0);
		node->create_child(node, "name", name, NULL, NULL, 0);

		uci_foreach_element(&s->options, el) {
			o = uci_to_option(el);
			if (UCI_TYPE_STRING == o->type)
				node->create_child(node, o->e.name, o->v.string, NULL, NULL, 0);
			else if (UCI_TYPE_LIST == o->type && !strcmp(o->e.name, "ring"))
				uci_foreach_element(&o->v.list, el_list) {
					o_list = uci_to_option(el_list);
					node->create_child(node, o->e.name, o_list->e.name, NULL, NULL, 0);
				}
		}
	}

	uci_unload(uci, asterisk);
	uci_free_context(uci);

	return rc;
}

struct rpc_method rpc[] = {
	{"start", rpc_start},
	{"stop", rpc_stop},
	{"restart", rpc_restart},
	{"reload", rpc_reload},
	{"disable", rpc_disable},
	{"enable", rpc_enable},
};

__unused struct module *init()
{
	m.rpcs = rpc;
	m.rpc_count = (sizeof(rpc) / sizeof(*(rpc)));
	m.ns = _ns;
	m.datastore = &root;

	create_store();
	context = uci_alloc_context();
	if (!context) {
		ERROR("no memory for uci");
	}

	if (uci_set_confdir(context, "/etc/config")) {
		ERROR("could not find config file");
	}

	return &m;
}

__unused void destroy()
{
	ds_free(root.child, 1);
	root.child = NULL;
	uci_free_context(context);
}
