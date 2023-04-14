import { ThenableWebDriver, Key } from 'selenium-webdriver'
import { BuildSetup } from './crossplatform.utils'
import {
  Channel,
  CreateCommunityModal,
  DebugModeModal,
  JoinCommunityModal,
  JoiningLoadingPanel,
  RegisterUsernameModal,
  StartingLoadingPanel
} from './selectors.crossplatform'
import getPort from 'get-port'

jest.setTimeout(450000)
describe('Restart by owner', () => {
  let buildSetup: BuildSetup
  let driver: ThenableWebDriver

  const customDataDir = `e2e_${(Math.random() * 10 ** 18).toString(36)}`

  // let port: number
  // let debugPort: number

  let generalChannel: Channel
  const username = 'testuser'
  const ownerMessages = ['Hi']

  beforeAll(async () => {
    const port = await getPort()
    const debugPort = await getPort()

    buildSetup = new BuildSetup({ port, debugPort, useDataDir: false })
    await buildSetup.createChromeDriver()
    driver = buildSetup.getDriver()
    await driver.getSession()
  })

  afterAll(async () => {
    await buildSetup.closeDriver()
    await buildSetup.killChromeDriver()
  })
  describe('Stages:', () => {
    if (process.env.TEST_MODE) {
      it('Close debug modal', async () => {
        const debugModal = new DebugModeModal(driver)
        await debugModal.close()
      })
    }

    it('User waits for the modal StartingLoadingPanel to disappear', async () => {
      const loadingPanel = new StartingLoadingPanel(driver)
      const isLoadingPanel = await loadingPanel.element.isDisplayed()
      await buildSetup.getTorPid()
      expect(isLoadingPanel).toBeTruthy()
    })

    it('User sees "join community" page and switches to "create community" view by clicking on the link', async () => {
      const joinModal = new JoinCommunityModal(driver)
      const isJoinModal = await joinModal.element.isDisplayed()
      expect(isJoinModal).toBeTruthy()

      if (!isJoinModal) {
        const generalChannel = new Channel(driver, 'general')
        const isGeneralChannel = await generalChannel.element.isDisplayed()

        expect(isGeneralChannel).toBeTruthy()
      } else {
        await joinModal.switchToCreateCommunity()
      }
    })

    it('User is on "Create community" page, enters valid community name and presses the button', async () => {
      const createModal = new CreateCommunityModal(driver)
      const isCreateModal = await createModal.element.isDisplayed()
      expect(isCreateModal).toBeTruthy()
      await createModal.typeCommunityName('testcommunity')
      await createModal.submit()
    })

    it('User sees "register username" page, enters the valid name and submits by clicking on the button', async () => {
      const registerModal = new RegisterUsernameModal(driver)
      const isRegisterModal = await registerModal.element.isDisplayed()

      expect(isRegisterModal).toBeTruthy()
      await registerModal.typeUsername(username)
      await registerModal.submit()
    })

    it('User waits for the modal JoiningLoadingPanel to disappear', async () => {
      const loadingPanelCommunity = new JoiningLoadingPanel(driver)
      const isLoadingPanelCommunity = await loadingPanelCommunity.element.isDisplayed()
      expect(isLoadingPanelCommunity).toBeTruthy()
    })

    it('User sees general channel', async () => {
      const generalChannel = new Channel(driver, 'general')
      const isGeneralChannel = await generalChannel.element.isDisplayed()
      const generalChannelText = await generalChannel.element.getText()
      expect(isGeneralChannel).toBeTruthy()
      expect(generalChannelText).toEqual('# general')
    })

    it('Send message', async () => {
      const isMessageInput = await generalChannel.messageInput.isDisplayed()
      expect(isMessageInput).toBeTruthy()
      await generalChannel.sendMessage(ownerMessages[0])
    })

    it('Visible message', async () => {
      const messages = await generalChannel.getUserMessages(username)
      const text = await messages[1].getText()
      expect(text).toEqual(ownerMessages[0])
    })

    it('Close app', async () => {
      await buildSetup.closeDriver()
      await buildSetup.killChromeDriver()
    })

    it('Restart - Prepare second setup and run app', async () => {
      console.log('restart - 1')
      const port = await getPort()
      const debugPort = await getPort()
      buildSetup = new BuildSetup({ port, debugPort, useDataDir: false })
      await buildSetup.createChromeDriver()
      driver = buildSetup.getDriver()
      await driver.getSession()
    })

    if (process.env.TEST_MODE) {
      it('Restart - Close debug modal', async () => {
        const debugModal = new DebugModeModal(driver)
        await debugModal.close()
      })
    }

    it('Restart - User waits for the modal StartingLoadingPanel to disappear', async () => {
      console.log('restart - 2')
      const loadingPanel = new StartingLoadingPanel(driver)
      const isLoadingPanel = await loadingPanel.element.isDisplayed()
      await buildSetup.getTorPid()
      expect(isLoadingPanel).toBeTruthy()
    })

    it('Restart - wait for channel', async () => {
      console.log('restart - 3')
      generalChannel = new Channel(driver, 'general')
      await generalChannel.element.isDisplayed()
      const isMessageInput = await generalChannel.messageInput.isDisplayed()
      expect(isMessageInput).toBeTruthy()
      console.log('FETCHING CHANNEL MESSAGES!')
      await new Promise<void>(resolve => setTimeout(() => resolve(), 15000))
    })
    it('Message is visible in a channel', async () => {
      console.log('restart - 4')
      const messages = await generalChannel.getUserMessages(username)
      const text = await messages[1].getText()
      expect(text).toEqual(ownerMessages[0])
    })
  })
})
