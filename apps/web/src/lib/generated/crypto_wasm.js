/* @ts-self-types="./crypto_wasm.d.ts" */

/**
 * Poignée du compte pseudonyme.
 *
 * Séparée de [`Client`] à dessein : un compte survit à ses appareils, et un appareil peut
 * exister le temps d'un appairage sans détenir la clé du compte. Les fusionner ferait croire
 * que l'un implique l'autre.
 *
 * **Cet objet détient la clé racine du compte.** La perdre équivaut à perdre le compte ; la
 * divulguer équivaut à le céder.
 */
export class AccountKey {
    static __wrap(ptr) {
        const obj = Object.create(AccountKey.prototype);
        obj.__wbg_ptr = ptr;
        AccountKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AccountKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_accountkey_free(ptr, 0);
    }
    /**
     * Signe l'appartenance d'un appareil à ce compte.
     * @param {string} handle
     * @param {string} device_id
     * @param {Uint8Array} auth_key
     * @param {Uint8Array} mls_key
     * @returns {Uint8Array}
     */
    attest(handle, device_id, auth_key, mls_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(handle, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(auth_key, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passArray8ToWasm0(mls_key, wasm.__wbindgen_export);
            const len3 = WASM_VECTOR_LEN;
            wasm.accountkey_attest(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v5 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v5;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Graine à transmettre à un appareil qu'on appaire. **Vaut le compte entier.**
     * @returns {Uint8Array}
     */
    exportSeed() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.accountkey_exportSeed(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Empreinte du compte, à comparer hors bande.
     *
     * Stable quand le compte gagne ou perd un appareil : la détection d'un appareil hostile
     * passe par la notification d'ajout, pas par un changement d'empreinte qui serait ignoré
     * à force de se produire légitimement.
     * @returns {string}
     */
    fingerprint() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.accountkey_fingerprint(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Reconstruit le compte depuis la graine reçue lors d'un appairage.
     * @param {Uint8Array} seed
     * @returns {AccountKey}
     */
    static fromSeed(seed) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.accountkey_fromSeed(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return AccountKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Crée un compte et retourne `{phrase, identityKey}`.
     * @returns {any}
     */
    static generate() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.accountkey_generate(retptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    identityKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.accountkey_identityKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Reconstruit le compte depuis sa phrase de récupération.
     * @param {string} phrase
     * @returns {AccountKey}
     */
    static restore(phrase) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.accountkey_restore(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return AccountKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Signe la révocation d'un appareil de ce compte.
     *
     * Le certificat est vérifiable par n'importe qui détenant la clé publique du compte :
     * c'est ce qui permet à un **autre** membre du groupe de commiter le retrait sans croire
     * le serveur sur parole.
     * @param {string} handle
     * @param {string} device_id
     * @param {bigint} revoked_at
     * @returns {Uint8Array}
     */
    revoke(handle, device_id, revoked_at) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(handle, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.accountkey_revoke(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, revoked_at);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Signe le passage de ce compte à une nouvelle clé d'identité.
     *
     * À appeler sur l'**ancien** compte, qui désigne ainsi son successeur.
     *
     * C'est la seule réponse réelle à un appareil volé : celui-ci détient la graine, donc le
     * compte entier, et le révoquer ne l'empêche pas d'en attester un nouveau. La rotation,
     * elle, rend invérifiables toutes les attestations d'un coup.
     * @param {string} handle
     * @param {Uint8Array} new_identity_key
     * @param {bigint} rotated_at
     * @returns {Uint8Array}
     */
    rotate(handle, new_identity_key, rotated_at) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(handle, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(new_identity_key, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.accountkey_rotate(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, rotated_at);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Clé symétrique du coffre de sauvegarde, dérivée à la demande.
     * @returns {Uint8Array}
     */
    vaultKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.accountkey_vaultKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) AccountKey.prototype[Symbol.dispose] = AccountKey.prototype.free;

/**
 * Poignée unique côté JavaScript : une identité d'appareil et ses conversations.
 *
 * Les conversations sont indexées par identifiant de groupe plutôt qu'exposées comme objets
 * séparés. Manipuler deux poignées appariées depuis JS — une identité, une conversation —
 * invite à les mélanger, et chiffrer avec la mauvaise identité est une erreur silencieuse.
 */
export class Client {
    static __wrap(ptr) {
        const obj = Object.create(Client.prototype);
        obj.__wbg_ptr = ptr;
        ClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ClientFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_client_free(ptr, 0);
    }
    /**
     * Applique le commit préparé par `invite`, une fois celui-ci publié.
     *
     * Retourne l'arbre de ratchet à jour, à transmettre à l'invité avec son Welcome. Il ne
     * peut pas être produit plus tôt : tant que le commit n'est pas appliqué, l'arbre ne
     * contient pas le nouveau membre et son Welcome serait rejeté.
     * @param {Uint8Array} group_id
     * @returns {Uint8Array}
     */
    applyPending(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_applyPending(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Commite les propositions en attente — typiquement la demande de sortie d'un membre.
     * @param {Uint8Array} group_id
     * @returns {Uint8Array}
     */
    commitPending(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_commitPending(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Identifiants des conversations ouvertes, à persister à côté de l'état pour pouvoir
     * les recharger via [`Client::restore`].
     * @returns {Uint8Array[]}
     */
    conversationIds() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_conversationIds(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayJsValueFromWasm0(r0, r1);
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Crée une identité d'appareil.
     *
     * `name` est transporté en clair dans le credential MLS et visible du serveur comme de
     * tous les membres du groupe. N'y mettez rien de sensible.
     * @param {string} name
     * @returns {Client}
     */
    static create(name) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(name, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_create(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Client.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Crée une conversation et retourne son identifiant de groupe.
     * @returns {Uint8Array}
     */
    createConversation() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_createConversation(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Crée un groupe administré. Le créateur en est l'admin, seul et unique.
     *
     * À réserver aux vrais groupes. Un 1-to-1 doit passer par `createConversation` : des rôles
     * n'y ont aucun sens, et le groupe plat est la forme correcte.
     * @param {string} admin
     * @returns {Uint8Array}
     */
    createGroup(admin) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(admin, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_createGroup(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} group_id
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    encrypt(group_id, plaintext) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_encrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Epoch courante du groupe. Deux membres à des epochs différentes ne peuvent pas se
     * lire : c'est la première chose à regarder quand un message ne passe pas.
     * @param {Uint8Array} group_id
     * @returns {bigint}
     */
    epoch(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_epoch(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getBigInt64(retptr + 8 * 0, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            return BigInt.asUintN(64, r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Exporte l'état complet des sessions.
     *
     * **Ce blob contient les clés privées en clair.** Il ne doit jamais atteindre
     * `localStorage`, ni un backup, ni le serveur. Le chiffrer d'abord avec une clé
     * `CryptoKey` non-extractable détenue dans IndexedDB.
     *
     * Ne jamais restaurer un état *ancien* : cela fait reculer le groupe d'epoch et rejoue
     * des clés déjà utilisées, ce qui détruit la forward secrecy.
     * @returns {Uint8Array}
     */
    exportState() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_exportState(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    fingerprint() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_fingerprint(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Prépare l'ajout d'un membre. Retourne `{commit, welcome}` **sans rien appliquer**.
     *
     * Les deux parties ne vont pas au même endroit : le `commit` aux membres déjà présents,
     * le `welcome` au seul invité.
     *
     * Le groupe reste à son epoch actuelle jusqu'à [`Client::applyPending`]. Publier d'abord,
     * appliquer ensuite : l'inverse casse le groupe sans recours si la publication échoue —
     * l'émetteur aurait changé d'epoch, les autres non, et le commit serait perdu.
     * @param {Uint8Array} group_id
     * @param {Uint8Array} key_package
     * @returns {any}
     */
    invite(group_id, key_package) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(key_package, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_invite(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Rejoint une conversation depuis un Welcome. Retourne l'identifiant de groupe.
     * @param {Uint8Array} welcome
     * @param {Uint8Array} ratchet_tree
     * @returns {Uint8Array}
     */
    join(welcome, ratchet_tree) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(welcome, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(ratchet_tree, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_join(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Demande à quitter le groupe. Retourne une **proposition**, pas un commit.
     *
     * La RFC 9420 interdit de se retirer soi-même dans un commit qu'on génère : un autre
     * membre doit la reprendre via `commitPending`. Conséquence à afficher honnêtement —
     * tant que personne ne commite, le départ n'a pas eu lieu et la conversation continue
     * d'être lue.
     * @param {Uint8Array} group_id
     * @returns {Uint8Array}
     */
    leaveGroup(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_leaveGroup(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Nom de cet appareil, tel qu'inscrit dans le credential MLS.
     * @returns {string}
     */
    name() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_name(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Empreintes des autres membres, à comparer hors bande.
     *
     * L'interface doit rendre cette comparaison possible et compréhensible. Sans elle, un
     * serveur malveillant peut se placer au milieu de deux sessions parfaitement chiffrées
     * sans qu'aucune vérification cryptographique ne le détecte.
     * @param {Uint8Array} group_id
     * @returns {any}
     */
    peerFingerprints(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_peerFingerprints(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Clés de signature MLS des autres membres, telles qu'elles figurent dans l'arbre.
     *
     * Vient de l'état authentifié, pas du serveur. C'est ce qui permet au client de constater
     * qu'un membre de l'arbre ne figure plus parmi les appareils actifs de son compte.
     * @param {Uint8Array} group_id
     * @returns {any}
     */
    peerSignatureKeys(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_peerSignatureKeys(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Traite un message entrant : applicatif ou changement de groupe.
     *
     * Le résultat doit être traité dans les deux cas. Ignorer un `groupChanged` laisse
     * l'appareil à une epoch périmée, et tout ce qui suit devient indéchiffrable.
     * @param {Uint8Array} group_id
     * @param {Uint8Array} message
     * @param {Uint8Array[]} revoked
     * @returns {any}
     */
    process(group_id, message, revoked) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArrayJsValueToWasm0(revoked, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.client_process(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Produit un KeyPackage à publier sur le serveur.
     *
     * **À usage unique.** Le serveur doit le retirer du stock dès qu'il le sert, et
     * l'appelant doit en réapprovisionner régulièrement : sans stock disponible, plus
     * personne ne peut ouvrir de conversation avec cet appareil.
     * @returns {Uint8Array}
     */
    publishKeyPackage() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_publishKeyPackage(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Prépare le retrait d'un membre, désigné par sa clé de signature MLS.
     *
     * C'est ce retrait — et non le filtrage côté serveur — qui prive effectivement l'appareil
     * de la suite : le commit re-clé l'arbre. Même discipline que `invite` : publier, puis
     * `applyPending`.
     * @param {Uint8Array} group_id
     * @param {Uint8Array} mls_key
     * @returns {Uint8Array}
     */
    removeMember(group_id, mls_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(mls_key, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_removeMember(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Reconstruit un client depuis un état exporté.
     *
     * `groupIds` est la liste des conversations à recharger. Le stockage MLS ne fournit pas
     * d'énumération : c'est à l'appelant de conserver cette liste, à côté de l'état.
     *
     * Ne restaurez **jamais** un état plus ancien que le dernier exporté : les groupes
     * reculeraient d'epoch et rejoueraient des clés déjà utilisées. Un état MLS n'est pas
     * une sauvegarde ordinaire — il ne doit exister qu'une seule copie vivante.
     * @param {Uint8Array} state
     * @param {Uint8Array[]} group_ids
     * @returns {Client}
     */
    static restore(state, group_ids) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(state, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(group_ids, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_restore(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Client.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Roster du groupe : `{admin, moderators}`, ou `null` si le groupe est plat.
     * @param {Uint8Array} group_id
     * @returns {any}
     */
    roster(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_roster(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Remplace les rôles du groupe. Comme tout commit, à publier avant `applyPending`.
     *
     * Passer un `admin` différent de l'actuel **transmet le groupe** : l'émetteur ne pourra
     * pas se le reprendre.
     * @param {Uint8Array} group_id
     * @param {string} admin
     * @param {string[]} moderators
     * @returns {Uint8Array}
     */
    setRoles(group_id, admin, moderators) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(admin, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArrayJsValueToWasm0(moderators, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.client_setRoles(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Clé symétrique du canal éphémère de ce groupe, pour l'epoch courante.
     *
     * **Ces octets ne doivent servir qu'aux signaux jetables.** Ils ne passent pas par le
     * ratchet applicatif, donc ils n'offrent aucune forward secrecy à l'intérieur d'une
     * epoch, et ils n'authentifient pas l'émetteur — la clé est celle du groupe. Y faire
     * transiter un message vaudrait annuler les deux propriétés pour lesquelles MLS a été
     * choisi.
     *
     * La clé change à chaque commit : un membre retiré perd ce canal en même temps que le
     * reste, sans traitement particulier.
     * @param {Uint8Array} group_id
     * @returns {Uint8Array}
     */
    signalKey(group_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_signalKey(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Empreinte de cet appareil, à afficher pour que le correspondant la compare.
     * Clé publique de signature MLS de cet appareil.
     *
     * Elle doit être attestée par le compte **en même temps** que la clé d'authentification
     * HTTP : attestées séparément, on pourrait recombiner l'attestation d'un appareil
     * légitime avec la clé MLS d'un appareil hostile.
     * @returns {Uint8Array}
     */
    signatureKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_signatureKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) Client.prototype[Symbol.dispose] = Client.prototype.free;

/**
 * Offre d'appairage détenue par le **nouvel** appareil.
 *
 * C'est lui qui affiche le QR, l'ancien qui scanne. Ce sens est obligatoire : un QR est
 * photographiable, il ne doit donc contenir aucun secret. Ici il ne porte qu'une clé publique
 * éphémère et une adresse de dépôt.
 */
export class Pairing {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PairingFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pairing_free(ptr, 0);
    }
    /**
     * Identifiant d'appairage : l'adresse de dépôt sur le serveur. Public, sans valeur seul.
     * @returns {Uint8Array}
     */
    id() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.pairing_id(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    constructor() {
        const ret = wasm.pairing_new();
        this.__wbg_ptr = ret;
        PairingFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Ouvre le paquet déposé par l'appareil d'origine.
     *
     * Consomme l'offre : le secret éphémère ne sert qu'une fois, ce qui interdit de rejouer
     * un ancien paquet contre la même clé. Un second appel échoue, délibérément.
     * @param {Uint8Array} sealed
     * @returns {any}
     */
    open(sealed) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(sealed, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.pairing_open(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Clé publique éphémère à publier dans le QR.
     * @returns {Uint8Array}
     */
    publicKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.pairing_publicKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) Pairing.prototype[Symbol.dispose] = Pairing.prototype.free;

/**
 * Empreinte d'un compte dont on ne détient que la clé publique.
 * @param {Uint8Array} identity_key
 * @returns {string}
 */
export function accountFingerprint(identity_key) {
    let deferred2_0;
    let deferred2_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(identity_key, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.accountFingerprint(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred2_0 = r0;
        deferred2_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Dérive la clé de déverrouillage locale depuis un mot de passe.
 *
 * Argon2id, 64 Mio, 3 passes. **Environ une seconde** : c'est le prix à payer une fois par
 * déverrouillage, et à chaque essai par un attaquant qui aurait obtenu la base.
 *
 * Cette fonction n'existe pas dans WebCrypto. PBKDF2, lui, y est — mais il ne coûte que du
 * calcul, ce qu'un GPU fait par milliards. Le coût mémoire d'Argon2id est ce qui ramène une
 * attaque parallèle au niveau d'un processeur ordinaire.
 *
 * Appeler cette fonction gèle le fil d'exécution pendant sa durée. À lancer depuis un Worker
 * si l'interface doit rester réactive.
 * @param {string} password
 * @param {Uint8Array} salt
 * @returns {Uint8Array}
 */
export function deriveUnlockKey(password, salt) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(password, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        wasm.deriveUnlockKey(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Message à signer pour ouvrir une session gateway.
 *
 * Retourne les octets à signer, **pas la signature** : la clé d'authentification de l'appareil
 * est une clé WebCrypto non extractible, qui ne quitte jamais le navigateur et n'entre donc
 * jamais dans ce module. La séparation est délibérée — c'est elle qui fait qu'un bug ici ne
 * peut pas divulguer la clé.
 *
 * Même argument que pour [`post_mac`] quant au lieu du calcul : le format canonique vit dans la
 * crate `attest`, et le réécrire en JavaScript le dupliquerait. Un octet de divergence, et
 * aucune session ne s'ouvre.
 * @param {string} device_id
 * @param {Uint8Array} nonce
 * @returns {Uint8Array}
 */
export function gatewayChallenge(device_id, nonce) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        wasm.gatewayChallenge(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Hash de feuille d'une entrée du journal, tel que le serveur doit l'avoir calculé.
 *
 * Le client le recalcule lui-même à partir du handle et de la clé qu'on lui sert : accepter le
 * hash fourni par le serveur reviendrait à lui demander de prouver ce qu'il affirme avec ce
 * qu'il affirme.
 * @param {string} handle
 * @param {Uint8Array} identity_key
 * @returns {Uint8Array}
 */
export function logLeaf(handle, identity_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(handle, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(identity_key, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        wasm.logLeaf(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Authentifie un dépôt d'enveloppe sans révéler qui dépose.
 *
 * # Ce que ce MAC dit au serveur
 *
 * Que le déposant détient la clé du groupe, donc qu'il en est membre. Rien de plus. Le serveur
 * n'a jamais eu besoin de savoir **qui** poste — seulement que le posteur a le droit de le
 * faire, pour ne pas servir de boîte aux lettres ouverte. Ce sont deux choses distinctes, et
 * la seconde suffit.
 *
 * L'expéditeur réel reste authentifié **par MLS**, à l'intérieur du chiffré : les
 * destinataires le lisent, le serveur non.
 *
 * # Pourquoi le calcul est fait ici et pas en JavaScript
 *
 * Le message authentifié a un format canonique, partagé avec le vérificateur. Le réécrire côté
 * client dupliquerait la définition — exactement ce que la crate `attest` existe pour
 * supprimer. Un octet de divergence, et tous les dépôts sont refusés.
 * @param {Uint8Array} posting_key
 * @param {Uint8Array} group_id
 * @param {Uint8Array} nonce
 * @param {Uint8Array} body
 * @returns {Uint8Array}
 */
export function postMac(posting_key, group_id, nonce, body) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(posting_key, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(nonce, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(body, wasm.__wbindgen_export);
        const len3 = WASM_VECTOR_LEN;
        wasm.postMac(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v5 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v5;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Scelle un paquet à destination du nouvel appareil, depuis les valeurs lues dans le QR.
 *
 * Retourne `{payload, confirmation}`. Le code de confirmation doit être **affiché des deux
 * côtés et comparé par l'utilisateur** : c'est ce qui atteste que les deux appareils parlent
 * bien du même échange.
 * @param {Uint8Array} offer_public
 * @param {Uint8Array} offer_id
 * @param {Uint8Array} plaintext
 * @returns {any}
 */
export function sealPairing(offer_public, offer_id, plaintext) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(offer_public, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(offer_id, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        wasm.sealPairing(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * MAC accompagnant le dépôt d'un **signal éphémère**.
 *
 * Jumeau de [`post_mac`], au domaine près — voir `attest::signal_message` pour la raison de
 * cette séparation. Il prouve la même chose : l'appartenance au groupe, pas l'identité.
 * @param {Uint8Array} posting_key
 * @param {Uint8Array} group_id
 * @param {Uint8Array} nonce
 * @param {Uint8Array} body
 * @returns {Uint8Array}
 */
export function signalMac(posting_key, group_id, nonce, body) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(posting_key, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(group_id, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(nonce, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(body, wasm.__wbindgen_export);
        const len3 = WASM_VECTOR_LEN;
        wasm.signalMac(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v5 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v5;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Vérifie une attestation d'appareil servie par le serveur.
 *
 * **À rappeler systématiquement côté client.** Le serveur vérifie déjà à l'écriture, mais
 * c'est précisément le serveur qu'on soupçonne : sa vérification n'est qu'un filtre précoce,
 * jamais une garantie. Voir le test
 * `un_appareil_fantome_injecte_en_sql_ne_passe_pas_la_verification_du_client`.
 * @param {Uint8Array} identity_key
 * @param {string} handle
 * @param {string} device_id
 * @param {Uint8Array} auth_key
 * @param {Uint8Array} mls_key
 * @param {Uint8Array} attestation
 * @returns {boolean}
 */
export function verifyAttestation(identity_key, handle, device_id, auth_key, mls_key, attestation) {
    const ptr0 = passArray8ToWasm0(identity_key, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(handle, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(auth_key, wasm.__wbindgen_export);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passArray8ToWasm0(mls_key, wasm.__wbindgen_export);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passArray8ToWasm0(attestation, wasm.__wbindgen_export);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.verifyAttestation(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
    return ret !== 0;
}

/**
 * Vérifie que le journal actuel **prolonge** celui qu'on avait déjà vu, sans réécriture.
 *
 * Sans ce contrôle, le serveur pourrait remplacer une clé déjà publiée et servir un journal
 * tout aussi cohérent : le journal ne prouverait plus rien sur le passé.
 * @param {number} from
 * @param {Uint8Array} old_root
 * @param {number} to
 * @param {Uint8Array} new_root
 * @param {Uint8Array[]} proof
 * @returns {boolean}
 */
export function verifyConsistency(from, old_root, to, new_root, proof) {
    const ptr0 = passArray8ToWasm0(old_root, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(new_root, wasm.__wbindgen_export);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArrayJsValueToWasm0(proof, wasm.__wbindgen_export);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyConsistency(from, ptr0, len0, to, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Vérifie qu'une clé figure bien dans le journal, à l'indice annoncé.
 *
 * **C'est ce qui ferme le trou du premier contact.** Les attestations empêchent le serveur
 * d'ajouter un appareil ; elles ne l'empêchent pas de servir sa propre clé de compte à
 * quelqu'un qui n'a rien à quoi comparer. Une preuve d'inclusion, elle, ne se fabrique pas.
 * @param {Uint8Array} leaf
 * @param {number} index
 * @param {number} size
 * @param {Uint8Array[]} proof
 * @param {Uint8Array} root
 * @returns {boolean}
 */
export function verifyInclusion(leaf, index, size, proof, root) {
    const ptr0 = passArray8ToWasm0(leaf, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArrayJsValueToWasm0(proof, wasm.__wbindgen_export);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(root, wasm.__wbindgen_export);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyInclusion(ptr0, len0, index, size, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Vérifie un certificat de révocation servi par le serveur.
 *
 * **À appeler systématiquement.** Un client qui croirait le serveur sur parole lui rendrait
 * le pouvoir de faire évincer les appareils de son choix — de la censure ciblée, durable, et
 * indiscernable d'une révocation légitime.
 * @param {Uint8Array} identity_key
 * @param {string} handle
 * @param {string} device_id
 * @param {bigint} revoked_at
 * @param {Uint8Array} revocation
 * @returns {boolean}
 */
export function verifyRevocation(identity_key, handle, device_id, revoked_at, revocation) {
    const ptr0 = passArray8ToWasm0(identity_key, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(handle, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(revocation, wasm.__wbindgen_export);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.verifyRevocation(ptr0, len0, ptr1, len1, ptr2, len2, revoked_at, ptr3, len3);
    return ret !== 0;
}

/**
 * Vérifie qu'une tête de journal a bien été signée par le journal.
 *
 * **Ce que cela prouve est étroit** : que la tête vient du journal. Pas qu'elle soit la seule
 * qu'il ait émise. Un serveur qui tient deux journaux signe deux têtes également valides ;
 * seule la comparaison entre clients l'attrape.
 * @param {Uint8Array} log_key
 * @param {bigint} size
 * @param {Uint8Array} root
 * @param {bigint} timestamp
 * @param {Uint8Array} signature
 * @returns {boolean}
 */
export function verifyTreeHead(log_key, size, root, timestamp, signature) {
    const ptr0 = passArray8ToWasm0(log_key, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(root, wasm.__wbindgen_export);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(signature, wasm.__wbindgen_export);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyTreeHead(ptr0, len0, size, ptr1, len1, timestamp, ptr2, len2);
    return ret !== 0;
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_408e67f47ca7b58b: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(getObject(arg1));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_5e4570eb24ffa122: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_a2790eb24c211ea0: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_e6f02f0ea5f20a32: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_6cff064c44e0d823: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_d154f1e671052120: function(arg0, arg1) {
            const obj = getObject(arg1);
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_bb96b2010945f0bc: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_35dba3c747ad7521: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbg_from_74f3d90e0ff11240: function(arg0) {
            const ret = Array.from(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments); },
        __wbg_length_36bd29c6848c2144: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_new_116be93542d39019: function() {
            const ret = new Array();
            return addHeapObject(ret);
        },
        __wbg_new_77cc4f4f472aeb81: function(arg0) {
            const ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_new_ebe3e0f6837f0879: function() {
            const ret = new Object();
            return addHeapObject(ret);
        },
        __wbg_new_from_slice_3eea173078478cfe: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_new_with_length_3ffc1c56427c525c: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbg_now_8b265300afd5f2b9: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_prototypesetcall_de8e0d9553586985: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments); },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            getObject(arg0)[takeObject(arg1)] = takeObject(arg2);
        },
        __wbg_set_a80955eb93b145c6: function(arg0, arg1, arg2) {
            getObject(arg0)[arg1 >>> 0] = takeObject(arg2);
        },
        __wbg_static_accessor_GLOBAL_THIS_466428f93b4eaa76: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_c7aea38d4de089bc: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_SELF_42d4fae05e59267a: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_WINDOW_e0db14a0eba6a812: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_subarray_a4cc58201c7359fd: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./crypto_wasm_bg.js": import0,
    };
}

const AccountKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_accountkey_free(ptr, 1));
const ClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_client_free(ptr, 1));
const PairingFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pairing_free(ptr, 1));

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function dropObject(idx) {
    if (idx < 1028) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(takeObject(mem.getUint32(i, true)));
    }
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export3(addHeapObject(e));
    }
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    const mem = getDataViewMemory0();
    for (let i = 0; i < array.length; i++) {
        mem.setUint32(ptr + 4 * i, addHeapObject(array[i]), true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        throw new Error('Le chemin du module WASM est obligatoire — voir loadCrypto() dans src/lib/wasm.ts');
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
