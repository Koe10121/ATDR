function loadSettingModuleWithMock () {
  jest.resetModules()

  const serviceMock = {
    settings: jest.fn(),
    authenticated: jest.fn()
  }

  jest.doMock('@/service/api', () => ({
    __esModule: true,
    default: serviceMock
  }))

  const settingModule = require('@/store/modules/Setting').default
  return {
    serviceMock,
    settingStatus: settingModule.modules.settingStatus,
    settingMessageAuthen: settingModule.modules.settingMessageAuthen,
    settingMessage: settingModule.modules.settingMessage,
    settingVerification: settingModule.modules.settingVerification
  }
}

describe('store/modules/Setting', () => {
  describe('settingStatus', () => {
    test('explorer maps groups and statuses correctly', async () => {
      const { serviceMock, settingStatus } = loadSettingModuleWithMock()
      const commit = jest.fn()

      serviceMock.settings
        .mockResolvedValueOnce({
          data: {
            data: [
              {
                _id: 'g1',
                key: 'AUTH',
                title: [{ key: 'th', value: 'กลุ่มยืนยันตัวตน' }, { key: 'en', value: 'Auth Group' }]
              }
            ]
          }
        })
        .mockResolvedValueOnce({
          data: {
            data: [
              {
                _id: 's1',
                group: { _id: 'g1', title: [{ key: 'en', value: 'Auth Group' }] },
                key: 'ACTIVE',
                title: [{ key: 'th', value: 'ใช้งาน' }, { key: 'en', value: 'Active' }],
                description: [{ key: 'th', value: 'คำอธิบาย' }, { key: 'en', value: 'Description' }],
                state: true
              }
            ]
          }
        })

      await settingStatus.actions.explorer({ commit })

      expect(serviceMock.settings).toHaveBeenNthCalledWith(1, 'groups', {})
      expect(serviceMock.settings).toHaveBeenNthCalledWith(2, 'status', {})
      expect(commit).toHaveBeenCalledWith('groups', [
        expect.objectContaining({
          _id: 'g1',
          key: 'AUTH',
          name: 'กลุ่มยืนยันตัวตน'
        })
      ])
      expect(commit).toHaveBeenCalledWith('items', [
        expect.objectContaining({
          _id: 's1',
          groupId: 'g1',
          groupName: 'Auth Group',
          key: 'ACTIVE',
          titleTh: 'ใช้งาน',
          titleEn: 'Active',
          statusText: 'Active'
        })
      ])
    })

    test('create throws when payload is invalid', async () => {
      const { serviceMock, settingStatus } = loadSettingModuleWithMock()
      const dispatch = jest.fn()

      await expect(settingStatus.actions.create({ dispatch }, { key: '', groupId: '' }))
        .rejects.toThrow('invalid_payload')
      expect(serviceMock.settings).not.toHaveBeenCalled()
    })

    test('create calls create-status and refreshes list', async () => {
      const { serviceMock, settingStatus } = loadSettingModuleWithMock()
      const dispatch = jest.fn().mockResolvedValue(true)

      serviceMock.settings.mockResolvedValue({ data: { data: [] } })
      await settingStatus.actions.create({ dispatch }, {
        groupId: 'g1',
        key: 'active_status',
        titleItems: [{ key: 'en', value: 'Active' }],
        descriptionItems: [{ key: 'en', value: 'description' }],
        state: true
      })

      expect(serviceMock.settings).toHaveBeenCalledWith('create-status', expect.objectContaining({
        group: 'g1',
        key: 'ACTIVE_STATUS',
        state: true
      }))
      expect(dispatch).toHaveBeenCalledWith('explorer')
    })
  })

  describe('settingMessageAuthen', () => {
    test('ensureStatusCatalog builds active/inactive/draft map from status list', async () => {
      const { serviceMock, settingMessageAuthen } = loadSettingModuleWithMock()
      const commit = jest.fn()

      serviceMock.settings.mockResolvedValue({
        data: {
          data: [
            { _id: '1', key: 'MESSAGE_ACTIVE', state: true },
            { _id: '2', key: 'MESSAGE_INACTIVE', state: false },
            { _id: '3', key: 'MESSAGE_DRAFT', state: false }
          ]
        }
      })

      const result = await settingMessageAuthen.actions.ensureStatusCatalog({
        state: { statusCatalog: { active: '', inactive: '', draft: '' } },
        commit
      })

      expect(serviceMock.settings).toHaveBeenCalledWith('status', {})
      expect(result).toEqual({ active: '1', inactive: '2', draft: '3' })
      expect(commit).toHaveBeenCalledWith('statusCatalog', { active: '1', inactive: '2', draft: '3' })
    })

    test('explorer maps auth message item for display', async () => {
      const { serviceMock, settingMessageAuthen } = loadSettingModuleWithMock()
      const commit = jest.fn()
      const dispatch = jest.fn().mockResolvedValue({ active: '1', inactive: '2', draft: '3' })

      serviceMock.authenticated.mockResolvedValue({
        data: {
          data: [
            {
              _id: 'm1',
              title: [{ key: 'en', value: 'Security Notice' }],
              description: [{ key: 'th', value: 'รายละเอียด' }],
              startDate: '2026-02-27T00:00:00.000Z',
              endDate: '2026-03-10T00:00:00.000Z',
              status: { _id: '1', key: 'MESSAGE_ACTIVE', state: true }
            }
          ]
        }
      })

      await settingMessageAuthen.actions.explorer({ commit, dispatch })

      expect(dispatch).toHaveBeenCalledWith('ensureStatusCatalog')
      expect(serviceMock.authenticated).toHaveBeenCalledWith('message', {}, {})
      expect(commit).toHaveBeenCalledWith('items', [
        expect.objectContaining({
          _id: 'm1',
          titleText: 'Security Notice',
          descriptionText: 'รายละเอียด',
          startDate: '2026-02-27',
          endDate: '2026-03-10',
          statusOption: 'active',
          isActive: true
        })
      ])
    })

    test('toggle calls update with inverted active status', async () => {
      const { settingMessageAuthen } = loadSettingModuleWithMock()
      const dispatch = jest.fn().mockResolvedValue(true)

      await settingMessageAuthen.actions.toggle({ dispatch }, {
        _id: 'm1',
        titleItems: [{ key: 'en', value: 'A' }],
        descriptionItems: [{ key: 'en', value: 'B' }],
        startDate: '2026-02-27',
        endDate: '2026-03-10',
        isActive: true
      })

      expect(dispatch).toHaveBeenCalledWith('update', expect.objectContaining({
        _id: 'm1',
        statusOption: 'inactive'
      }))
    })
  })

  describe('settingMessage', () => {
    test('explorer maps setting message list', async () => {
      const { serviceMock, settingMessage } = loadSettingModuleWithMock()
      const commit = jest.fn()

      serviceMock.settings.mockResolvedValue({
        data: {
          data: [
            {
              _id: 'msg-1',
              number: 1001,
              code: 9001,
              message: [{ key: 'th', value: 'แจ้งเตือน' }, { key: 'en', value: 'Notification' }]
            }
          ]
        }
      })

      await settingMessage.actions.explorer({ commit })

      expect(serviceMock.settings).toHaveBeenCalledWith('messages', {})
      expect(commit).toHaveBeenCalledWith('items', [
        expect.objectContaining({
          _id: 'msg-1',
          number: 1001,
          code: 9001,
          messageTh: 'แจ้งเตือน',
          messageEn: 'Notification'
        })
      ])
    })

    test('create sends normalized payload and refreshes explorer', async () => {
      const { serviceMock, settingMessage } = loadSettingModuleWithMock()
      const dispatch = jest.fn().mockResolvedValue(true)

      serviceMock.settings.mockResolvedValue({ data: { data: [] } })

      await settingMessage.actions.create({ dispatch }, {
        number: 12,
        code: 34,
        messageItems: [{ key: 'th', value: 'ทดสอบ' }, { key: 'en', value: 'Test' }]
      })

      expect(serviceMock.settings).toHaveBeenCalledWith('create-setting-message', {
        _id: null,
        number: 12,
        code: 34,
        message: [{ key: 'th', value: 'ทดสอบ' }, { key: 'en', value: 'Test' }],
        description: []
      })
      expect(dispatch).toHaveBeenCalledWith('explorer')
    })
  })

  describe('settingVerification', () => {
    test('explorer maps verification and reference options', async () => {
      const { serviceMock, settingVerification } = loadSettingModuleWithMock()
      const commit = jest.fn()

      serviceMock.settings
        .mockResolvedValueOnce({
          data: {
            data: [{
              _id: 'v1',
              title: [{ key: 'en', value: 'Check Profile' }],
              description: [{ key: 'th', value: 'ตรวจสอบข้อมูล' }],
              group: { _id: 'g1', title: [{ key: 'en', value: 'Account Group' }] },
              status: { _id: 's1', title: [{ key: 'th', value: 'ใช้งาน' }] }
            }]
          }
        })
        .mockResolvedValueOnce({
          data: {
            data: [{
              _id: 'g1',
              key: 'ACCOUNT',
              title: [{ key: 'en', value: 'Account Group' }]
            }]
          }
        })
        .mockResolvedValueOnce({
          data: {
            data: [{
              _id: 's1',
              key: 'ACTIVE',
              title: [{ key: 'th', value: 'ใช้งาน' }],
              state: true
            }]
          }
        })

      await settingVerification.actions.explorer({ commit })

      expect(serviceMock.settings).toHaveBeenNthCalledWith(1, 'verification', {})
      expect(serviceMock.settings).toHaveBeenNthCalledWith(2, 'groups', {})
      expect(serviceMock.settings).toHaveBeenNthCalledWith(3, 'status', {})
      expect(commit).toHaveBeenCalledWith('items', [
        expect.objectContaining({
          _id: 'v1',
          titleEn: 'Check Profile',
          groupId: 'g1',
          statusId: 's1'
        })
      ])
      expect(commit).toHaveBeenCalledWith('groups', [expect.any(Object)])
      expect(commit).toHaveBeenCalledWith('statuses', [expect.any(Object)])
    })

    test('update validates payload and calls api', async () => {
      const { serviceMock, settingVerification } = loadSettingModuleWithMock()
      const dispatch = jest.fn().mockResolvedValue(true)

      serviceMock.settings.mockResolvedValue({ data: { data: [] } })

      await settingVerification.actions.update({ dispatch }, {
        _id: 'v9',
        titleItems: [{ key: 'en', value: 'Review Item' }],
        descriptionItems: [{ key: 'th', value: 'คำอธิบาย' }],
        groupId: 'g9',
        statusId: 's9'
      })

      expect(serviceMock.settings).toHaveBeenCalledWith('update-verification', {
        _id: 'v9',
        title: [{ key: 'en', value: 'Review Item' }],
        description: [{ key: 'th', value: 'คำอธิบาย' }],
        group: 'g9',
        status: 's9'
      })
      expect(dispatch).toHaveBeenCalledWith('explorer')
    })
  })
})
