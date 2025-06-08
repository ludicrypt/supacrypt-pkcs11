/**
 * @file object_cache.cpp
 * @brief Implementation of object cache management
 */

#include "object_cache.h"
#include "supacrypt/pkcs11/pkcs11.h"
#include <algorithm>
#include <cstring>
#include <shared_mutex>

namespace supacrypt {
namespace pkcs11 {

ObjectCache::ObjectCache() {
    // Initialize with a reasonable starting handle value
    nextHandle_.store(1000);
}

ObjectCache::~ObjectCache() {
    clear();
}

CK_OBJECT_HANDLE ObjectCache::addObject(const std::string& keyId, CK_OBJECT_CLASS objClass) {
    if (keyId.empty()) {
        return CK_INVALID_HANDLE;
    }

    std::unique_lock<std::shared_mutex> lock(cacheMutex_);

    CK_OBJECT_HANDLE handle = nextHandle_.fetch_add(1);
    ObjectEntry entry(handle, keyId, objClass);

    // Add default attributes based on object class
    addDefaultAttributes(entry);

    objects_[handle] = std::move(entry);
    return handle;
}

bool ObjectCache::getObject(CK_OBJECT_HANDLE handle, ObjectEntry& entry) const {
    std::shared_lock<std::shared_mutex> lock(cacheMutex_);

    auto it = objects_.find(handle);
    if (it == objects_.end()) {
        return false;
    }

    entry = it->second;
    return true;
}

bool ObjectCache::removeObject(CK_OBJECT_HANDLE handle) {
    std::unique_lock<std::shared_mutex> lock(cacheMutex_);

    auto it = objects_.find(handle);
    if (it == objects_.end()) {
        return false;
    }

    objects_.erase(it);
    return true;
}

std::vector<CK_OBJECT_HANDLE> ObjectCache::findObjects(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count) const {
    std::vector<CK_OBJECT_HANDLE> results;

    if (!pTemplate && count > 0) {
        return results;
    }

    std::shared_lock<std::shared_mutex> lock(cacheMutex_);

    for (const auto& [handle, entry] : objects_) {
        bool matches = true;

        // Check if object matches all template attributes
        for (CK_ULONG i = 0; i < count && matches; ++i) {
            const CK_ATTRIBUTE& templateAttr = pTemplate[i];

            auto attrIt = entry.attributes.find(templateAttr.type);
            if (attrIt == entry.attributes.end()) {
                matches = false;
                continue;
            }

            matches = attributeMatches(attrIt->second, templateAttr);
        }

        if (matches) {
            results.push_back(handle);
        }
    }

    return results;
}

CK_RV ObjectCache::setAttribute(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_TYPE type, 
                               const std::vector<uint8_t>& value) {
    std::unique_lock<std::shared_mutex> lock(cacheMutex_);

    auto it = objects_.find(handle);
    if (it == objects_.end()) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    // Check if attribute is modifiable
    switch (type) {
        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_MODIFIABLE:
        case CKA_LABEL:
            // These are modifiable
            break;
        case CKA_CLASS:
        case CKA_KEY_TYPE:
        case CKA_ID:
            // These are typically read-only after creation
            return CKR_ATTRIBUTE_READ_ONLY;
        default:
            // For simplicity, allow modification of other attributes
            break;
    }

    it->second.attributes[type] = value;
    return CKR_OK;
}

CK_RV ObjectCache::getAttribute(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_TYPE type, 
                               std::vector<uint8_t>& value) const {
    std::shared_lock<std::shared_mutex> lock(cacheMutex_);

    auto it = objects_.find(handle);
    if (it == objects_.end()) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    auto attrIt = it->second.attributes.find(type);
    if (attrIt == it->second.attributes.end()) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    // Check if attribute is sensitive
    switch (type) {
        case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_COEFFICIENT:
        case CKA_VALUE:
            // Private key components are sensitive
            if (it->second.objectClass == CKO_PRIVATE_KEY) {
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            break;
        default:
            break;
    }

    value = attrIt->second;
    return CKR_OK;
}

void ObjectCache::clear() {
    std::unique_lock<std::shared_mutex> lock(cacheMutex_);
    objects_.clear();
    nextHandle_.store(1000);
}

size_t ObjectCache::size() const {
    std::shared_lock<std::shared_mutex> lock(cacheMutex_);
    return objects_.size();
}

bool ObjectCache::attributeMatches(const std::vector<uint8_t>& objectAttr, 
                                  const CK_ATTRIBUTE& templateAttr) const {
    if (templateAttr.pValue == nullptr) {
        return true; // NULL value in template matches any value
    }

    if (objectAttr.size() != templateAttr.ulValueLen) {
        return false;
    }

    return std::memcmp(objectAttr.data(), templateAttr.pValue, templateAttr.ulValueLen) == 0;
}

void ObjectCache::addDefaultAttributes(ObjectEntry& entry) {
    // Add default attributes based on object class
    auto& attrs = entry.attributes;

    // Common attributes for all objects
    attrs[CKA_CLASS] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&entry.objectClass),
                                           reinterpret_cast<const uint8_t*>(&entry.objectClass) + sizeof(CK_OBJECT_CLASS));

    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;

    attrs[CKA_TOKEN] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                           reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));

    attrs[CKA_PRIVATE] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckFalse),
                                             reinterpret_cast<const uint8_t*>(&ckFalse) + sizeof(CK_BBOOL));

    attrs[CKA_MODIFIABLE] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                                 reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));

    // Set backend key ID as the object ID
    attrs[CKA_ID] = std::vector<uint8_t>(entry.backendKeyId.begin(), entry.backendKeyId.end());

    // Object class specific attributes
    switch (entry.objectClass) {
        case CKO_PUBLIC_KEY:
            attrs[CKA_ENCRYPT] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                                     reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));
            attrs[CKA_VERIFY] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                                    reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));
            attrs[CKA_WRAP] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckFalse),
                                                  reinterpret_cast<const uint8_t*>(&ckFalse) + sizeof(CK_BBOOL));
            break;

        case CKO_PRIVATE_KEY:
            attrs[CKA_DECRYPT] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                                     reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));
            attrs[CKA_SIGN] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                                  reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));
            attrs[CKA_UNWRAP] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckFalse),
                                                    reinterpret_cast<const uint8_t*>(&ckFalse) + sizeof(CK_BBOOL));
            attrs[CKA_SENSITIVE] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckTrue),
                                                       reinterpret_cast<const uint8_t*>(&ckTrue) + sizeof(CK_BBOOL));
            attrs[CKA_EXTRACTABLE] = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ckFalse),
                                                         reinterpret_cast<const uint8_t*>(&ckFalse) + sizeof(CK_BBOOL));
            break;

        default:
            break;
    }
}

} // namespace pkcs11
} // namespace supacrypt