import React from 'react'
import { shallow } from 'enzyme'

import { ChannelMenuAction } from './ChannelMenuAction'

import { MuiThemeProvider } from '@material-ui/core'
import theme from '../../../theme'

describe('ChannelMenuAction', () => {
  it('renders component', () => {
    const result = shallow(
      <MuiThemeProvider theme={theme}>
        <ChannelMenuAction
          onInfo={jest.fn()}
          onMute={jest.fn()}
          onDelete={jest.fn()}
          onUnmute={jest.fn()}
          onSettings={jest.fn()}
          openNotificationsTab={jest.fn()}
          mutedFlag
          disableSettings
          notificationFilter={1}
        />
      </MuiThemeProvider>
    )
    expect(result).toMatchSnapshot()
  })
})