/**
 * @file object_cache.h
 * @brief Object cache management for PKCS#11 objects
 */

#ifndef SUPACRYPT_PKCS11_OBJECT_CACHE_H
#define SUPACRYPT_PKCS11_OBJECT_CACHE_H

#include "supacrypt/pkcs11/pkcs11.h"
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <map>
#include <atomic>

namespace supacrypt {
namespace pkcs11 {

/**
 * @brief Object entry in the cache
 */
struct ObjectEntry {
    CK_OBJECT_HANDLE handle;
    std::string backendKeyId;
    CK_OBJECT_CLASS objectClass;
    std::map<CK_ATTRIBUTE_TYPE, std::vector<uint8_t>> attributes;
    
    /**
     * @brief Constructor
     * @param h Object handle
     * @param keyId Backend key identifier
     * @param objClass Object class
     */
    ObjectEntry(CK_OBJECT_HANDLE h, const std::string& keyId, CK_OBJECT_CLASS objClass)
        : handle(h), backendKeyId(keyId), objectClass(objClass) {}
};

/**
 * @brief Thread-safe object cache for PKCS#11 objects
 * 
 * Manages the mapping between PKCS#11 object handles and backend
 * key identifiers, along with cached attributes.
 */
class ObjectCache {
public:
    /**
     * @brief Constructor
     */
    ObjectCache();

    /**
     * @brief Destructor
     */
    ~ObjectCache();

    /**
     * @brief Add an object to the cache
     * @param keyId Backend key identifier
     * @param objClass Object class
     * @return Object handle
     */
    CK_OBJECT_HANDLE addObject(const std::string& keyId, CK_OBJECT_CLASS objClass);

    /**
     * @brief Get an object from the cache
     * @param handle Object handle
     * @param entry Reference to store object entry
     * @return true if object found
     */
    bool getObject(CK_OBJECT_HANDLE handle, ObjectEntry& entry) const;

    /**
     * @brief Remove an object from the cache
     * @param handle Object handle
     * @return true if object was removed
     */
    bool removeObject(CK_OBJECT_HANDLE handle);

    /**
     * @brief Find objects matching template
     * @param pTemplate Attribute template
     * @param count Template attribute count
     * @return Vector of matching object handles
     */
    std::vector<CK_OBJECT_HANDLE> findObjects(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count) const;

    /**
     * @brief Set attribute for an object
     * @param handle Object handle
     * @param type Attribute type
     * @param value Attribute value
     * @return CK_RV Return code
     */
    CK_RV setAttribute(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_TYPE type, 
                      const std::vector<uint8_t>& value);

    /**
     * @brief Get attribute from an object
     * @param handle Object handle
     * @param type Attribute type
     * @param value Reference to store attribute value
     * @return CK_RV Return code
     */
    CK_RV getAttribute(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_TYPE type, 
                      std::vector<uint8_t>& value) const;

    /**
     * @brief Clear all objects from the cache
     */
    void clear();

    /**
     * @brief Get number of objects in cache
     * @return Object count
     */
    size_t size() const;

private:
    mutable std::shared_mutex cacheMutex_;
    std::unordered_map<CK_OBJECT_HANDLE, ObjectEntry> objects_;
    std::atomic<CK_OBJECT_HANDLE> nextHandle_{1000};

    /**
     * @brief Check if attribute matches template value
     * @param objectAttr Object attribute value
     * @param templateAttr Template attribute
     * @return true if matches
     */
    bool attributeMatches(const std::vector<uint8_t>& objectAttr, 
                         const CK_ATTRIBUTE& templateAttr) const;

    /**
     * @brief Add default attributes for object class
     * @param entry Object entry to populate
     */
    void addDefaultAttributes(ObjectEntry& entry);
};

} // namespace pkcs11
} // namespace supacrypt

#endif // SUPACRYPT_PKCS11_OBJECT_CACHE_H